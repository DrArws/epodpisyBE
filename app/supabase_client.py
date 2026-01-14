"""
Supabase client module for database operations.
Uses anon key + user JWT for RLS-based access control.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple
from contextvars import ContextVar

import httpx
from supabase import create_client, Client

from app.config import get_settings, Settings
from app.models import (
    Document,
    DocumentEvent,
    EventType,
    SignerStatus,
    DocumentStatus,
    SigningSession,
)
from app.utils.datetime_utils import utc_now, parse_db_timestamp, is_within_window

logger = logging.getLogger(__name__)

# Context variable to store user's JWT token for the current request
_current_user_token: ContextVar[Optional[str]] = ContextVar("current_user_token", default=None)


def set_user_token(token: str) -> None:
    """Set the current user's JWT token for Supabase RLS."""
    _current_user_token.set(token)


def get_user_token() -> Optional[str]:
    """Get the current user's JWT token."""
    return _current_user_token.get()


def clear_user_token() -> None:
    """Clear the current user's JWT token."""
    _current_user_token.set(None)


class SupabaseClient:
    """Supabase client wrapper using anon key + user JWT for RLS."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._base_client: Optional[Client] = None
        self._http_client = httpx.AsyncClient(base_url=self.settings.supabase_url)

    @property
    def client(self) -> Client:
        """Get client with current user's JWT token for RLS."""
        if self._base_client is None:
            self._base_client = create_client(
                self.settings.supabase_url,
                self.settings.supabase_anon_key,
            )

        # Set user's JWT token if available (for RLS)
        user_token = get_user_token()
        if user_token:
            self._base_client.postgrest.auth(user_token)
        else:
            # Reset to anon key if no user token
            self._base_client.postgrest.auth(self.settings.supabase_anon_key)

        return self._base_client

    def table(self, table_name: str):
        """Get a table reference with current auth context."""
        return self.client.table(table_name)

    async def admin_insert(self, table_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Insert data via admin-proxy Edge Function (bypasses RLS).
        Used when no user JWT is available (e.g., admin secret auth).
        """
        url = f"/functions/v1/admin-proxy/{table_name}"
        headers = {
            "Content-Type": "application/json",
            "X-Admin-Secret": self.settings.admin_api_secret,
        }

        logger.info(f"admin_insert: POST {url} for table {table_name}")
        try:
            response = await self._http_client.post(url, headers=headers, json=data)
            logger.info(f"admin_insert: response status={response.status_code}")
            response.raise_for_status()
            result = response.json()
            logger.info(f"admin_insert: success, result keys={list(result.keys()) if isinstance(result, dict) else 'list'}")
        except Exception as e:
            logger.error(f"admin_insert FAILED for {table_name}: {e}")
            raise

        # Handle different response formats from admin-proxy:
        # 1. Plain array: [{...}] -> return first element
        # 2. Wrapped array: {"data": [{...}]} -> return data[0]
        # 3. Direct object: {"id": ...} -> return as is
        if isinstance(result, list):
            return result[0] if result else {}
        if isinstance(result, dict) and "data" in result and isinstance(result["data"], list):
            return result["data"][0] if result["data"] else {}
        return result

    async def admin_update(self, table_name: str, record_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update data via admin-proxy Edge Function (bypasses RLS).
        """
        url = f"/functions/v1/admin-proxy/{table_name}/{record_id}"
        headers = {
            "Content-Type": "application/json",
            "X-Admin-Secret": self.settings.admin_api_secret,
        }

        logger.info(f"admin_update: PATCH {url} for {table_name}/{record_id[:8]}...")
        try:
            response = await self._http_client.patch(url, headers=headers, json=data)
            logger.info(f"admin_update: response status={response.status_code}")
            if response.status_code != 200:
                logger.warning(f"admin_update: response body='{response.text}'")
            response.raise_for_status()
            result = response.json()
            logger.info(f"admin_update: success for {table_name}/{record_id[:8]}...")
            return result
        except Exception as e:
            logger.error(f"admin_update: FAILED for {table_name}/{record_id[:8]}..., error={e}")
            raise

    async def admin_select(
        self,
        table_name: str,
        filters: Dict[str, Any],
        single: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """
        Select data via admin-proxy Edge Function (bypasses RLS).
        Used when no user JWT is available.
        """
        # Build query string from filters
        query_parts = []
        for k, v in filters.items():
            if isinstance(v, tuple) and len(v) == 2:
                op, val = v
                query_parts.append(f"{k}={op}.{val}")
            else:
                query_parts.append(f"{k}=eq.{v}")
        query_params = "&".join(query_parts)
        url = f"/functions/v1/admin-proxy/{table_name}?{query_params}"
        headers = {
            "Content-Type": "application/json",
            "X-Admin-Secret": self.settings.admin_api_secret,
        }

        logger.info(f"admin_select: GET {url}")
        logger.debug(f"admin_select: headers={headers}")

        response = await self._http_client.get(url, headers=headers)

        logger.info(f"admin_select: response status={response.status_code}")
        if response.status_code != 200:
            logger.warning(f"admin_select: response body='{response.text}'")

        response.raise_for_status()
        result = response.json()

        # Handle response format
        if isinstance(result, list):
            if single:
                return result[0] if result else None
            return result
        if isinstance(result, dict) and "data" in result:
            data = result["data"]
            if single:
                return data[0] if data else None
            return data
        return result

    # Document operations
    async def get_document(self, document_id: str, workspace_id: str) -> Optional[Document]:
        """
        Get a document by ID, scoped to workspace.
        Uses admin_select to bypass RLS (Google ID Token != Supabase JWT).
        """
        # Always use admin_select since we don't have Supabase JWT
        result = await self.admin_select(
            "documents",
            {"id": document_id, "workspace_id": workspace_id},
            single=True,
        )

        if not result:
            return None

        return Document(**result)

    async def update_document(
        self,
        document_id: str,
        workspace_id: str,
        updates: Dict[str, Any],
    ) -> Document:
        """
        Update a document, scoped to workspace.
        Uses admin_update to bypass RLS.
        """
        updates["updated_at"] = utc_now().isoformat()

        result = await self.admin_update("documents", document_id, updates)

        if not result:
            raise ValueError(f"Document not found: {document_id}")

        return Document(**result)

    def get_document_for_signing(self, document_id: str) -> Optional[Dict]:
        """
        Get document with all signers for signing operations.
        No workspace check - used with validated signing token.
        Uses anon key which may be blocked by RLS - prefer get_document_for_signing_admin.
        """
        result = self.table("documents").select(
            "*, document_signers(*)"
        ).eq("id", document_id).single().execute()

        return result.data

    async def get_document_for_signing_admin(self, document_id: str) -> Optional[Dict]:
        """
        Get document for signing operations via admin proxy (bypasses RLS).
        Used by public signing endpoints where no user JWT is available.
        """
        result = await self.admin_select(
            "documents",
            {"id": document_id},
            single=True,
        )
        return result

    # Signer operations
    async def get_signers(self, document_id: str, workspace_id: str) -> List[Dict]:
        """Get all signers for a document. Uses admin_select to bypass RLS."""
        result = await self.admin_select(
            "document_signers",
            {"document_id": document_id, "workspace_id": workspace_id},
            single=False,
        )

        return result or []

    async def update_signer(
        self,
        signer_id: str,
        workspace_id: str,
        updates: Dict[str, Any],
    ) -> Dict:
        """Update a signer record. Uses admin_update to bypass RLS."""
        updates["updated_at"] = utc_now().isoformat()

        result = await self.admin_update("document_signers", signer_id, updates)

        if not result:
            raise ValueError(f"Signer not found: {signer_id}")

        return result

    def get_pending_signers_count(self, document_id: str) -> int:
        """Get count of signers who haven't signed yet."""
        result = self.table("document_signers").select(
            "id", count="exact"
        ).eq(
            "document_id", document_id
        ).neq(
            "status", SignerStatus.SIGNED.value
        ).execute()

        return result.count or 0

    # Signing session operations
    def get_signing_session(
        self,
        token_hash: str,
    ) -> Optional[Dict]:
        """Get signing session by token hash."""
        result = self.table("signing_sessions").select(
            "*, document_signers(*)"
        ).eq("token_hash", token_hash).single().execute()

        return result.data

    async def get_signing_session_admin(
        self,
        token_hash: str,
    ) -> Optional[Dict]:
        """
        Get signing session by token hash via admin proxy (bypasses RLS).
        Used by public signing endpoints.
        """
        result = await self.admin_select(
            "signing_sessions",
            {"token_hash": token_hash},
            single=True,
        )

        if not result:
            return None

        # Get associated signer data
        signer_id = result.get("signer_id")
        if signer_id:
            signer = await self.admin_select(
                "document_signers",
                {"id": signer_id},
                single=True,
            )
            result["document_signers"] = signer

        return result

    async def update_signing_session(
        self,
        session_id: str,
        updates: Dict[str, Any],
    ) -> Dict:
        """Update a signing session. Uses admin_update to bypass RLS."""
        updates["updated_at"] = utc_now().isoformat()

        result = await self.admin_update("signing_sessions", session_id, updates)

        if not result:
            raise ValueError(f"Session not found: {session_id}")

        return result

    def try_acquire_signing_lock(
        self,
        session_id: str,
        idempotency_key: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict], str]:
        """
        Atomically try to acquire signing lock for a session.
        NOTE: This version uses direct table access - use try_acquire_signing_lock_admin for public endpoints.
        """
        now = utc_now()

        current = self.table("signing_sessions").select(
            "id, signed_at, idempotency_key, idempotency_response, signing_started_at"
        ).eq("id", session_id).maybeSingle().execute()

        if not current.data:
            logger.warning(f"try_acquire_signing_lock: session not found, id={session_id[:8]}...")
            return False, None, "SESSION_NOT_FOUND"

        data = current.data

        if data.get("signed_at"):
            cached = data.get("idempotency_response")
            return False, cached, "ALREADY_SIGNED"

        if idempotency_key and data.get("idempotency_key") == idempotency_key:
            cached = data.get("idempotency_response")
            if cached:
                return False, cached, "IDEMPOTENT_REPLAY"

        signing_started = data.get("signing_started_at")
        if signing_started:
            started_at = parse_db_timestamp(signing_started)
            if started_at and (now - started_at).total_seconds() < 120:
                return False, None, "IN_PROGRESS"

        update_data = {
            "signing_started_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        if idempotency_key:
            update_data["idempotency_key"] = idempotency_key

        result = self.table("signing_sessions").update(update_data).eq(
            "id", session_id
        ).is_("signed_at", "null").execute()

        if not result.data:
            return False, None, "RACE_LOST"

        return True, None, "ACQUIRED"

    async def try_acquire_signing_lock_admin(
        self,
        session_id: str,
        idempotency_key: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict], str]:
        """
        Atomically try to acquire signing lock for a session (admin proxy version).
        Use this for public endpoints that bypass RLS.
        """
        now = utc_now()

        # Get current state via admin proxy
        data = await self.admin_select("signing_sessions", {"id": session_id}, single=True)

        if not data:
            logger.warning(f"try_acquire_signing_lock_admin: session not found, id={session_id[:8]}...")
            return False, None, "SESSION_NOT_FOUND"

        if data.get("signed_at"):
            cached = data.get("idempotency_response")
            return False, cached, "ALREADY_SIGNED"

        if idempotency_key and data.get("idempotency_key") == idempotency_key:
            cached = data.get("idempotency_response")
            if cached:
                return False, cached, "IDEMPOTENT_REPLAY"

        signing_started = data.get("signing_started_at")
        if signing_started:
            started_at = parse_db_timestamp(signing_started)
            if started_at and (now - started_at).total_seconds() < 120:
                return False, None, "IN_PROGRESS"

        # Acquire lock via admin proxy
        update_data = {
            "signing_started_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        if idempotency_key:
            update_data["idempotency_key"] = idempotency_key

        try:
            await self.admin_update("signing_sessions", session_id, update_data)
            return True, None, "ACQUIRED"
        except Exception as e:
            logger.warning(f"try_acquire_signing_lock_admin: update failed: {e}")
            return False, None, "RACE_LOST"

    def store_signing_response(
        self,
        session_id: str,
        response_data: Dict[str, Any],
    ) -> None:
        """Store the signing response for idempotent replay."""
        self.table("signing_sessions").update({
            "idempotency_response": response_data,
            "updated_at": utc_now().isoformat(),
        }).eq("id", session_id).execute()

    async def store_signing_response_admin(
        self,
        session_id: str,
        response_data: Dict[str, Any],
    ) -> None:
        """Store the signing response for idempotent replay (admin proxy version)."""
        await self.admin_update("signing_sessions", session_id, {
            "idempotency_response": response_data,
            "updated_at": utc_now().isoformat(),
        })

    async def release_signing_lock_admin(
        self,
        session_id: str,
        success: bool = False,
        signed_at: Optional[datetime] = None,
    ) -> None:
        """
        Release signing lock after completion or on error.

        Args:
            session_id: Session ID
            success: True if signing completed successfully
            signed_at: Timestamp when signed (if success=True)
        """
        if success and signed_at:
            # Success: set signed_at, clear signing_started_at
            await self.admin_update("signing_sessions", session_id, {
                "signed_at": signed_at.isoformat(),
                "signing_started_at": None,
                "updated_at": utc_now().isoformat(),
            })
        else:
            # Error/rollback: just clear signing_started_at
            await self.admin_update("signing_sessions", session_id, {
                "signing_started_at": None,
                "updated_at": utc_now().isoformat(),
            })

    def check_otp_rate_limit(
        self,
        session_id: str,
        max_sends_per_hour: int = 5,
        max_verify_attempts: int = 5,
    ) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Check OTP rate limits from DB columns.

        Returns:
            (allowed, error_message, retry_after_seconds)
        """
        result = self.table("signing_sessions").select(
            "otp_sent_count, otp_last_sent_at, otp_verify_attempts, otp_locked_until"
        ).eq("id", session_id).single().execute()

        if not result.data:
            return False, "Session not found", None

        data = result.data
        now = utc_now()

        # Check if locked
        locked_until = parse_db_timestamp(data.get("otp_locked_until"))
        if locked_until and locked_until > now:
            retry_after = int((locked_until - now).total_seconds())
            return False, "Too many attempts. Please try again later.", retry_after

        # Check hourly send limit
        otp_sent_count = data.get("otp_sent_count") or 0
        last_sent = parse_db_timestamp(data.get("otp_last_sent_at"))

        if last_sent:
            # Reset counter if more than 1 hour since last send
            if (now - last_sent).total_seconds() > 3600:
                otp_sent_count = 0

        if otp_sent_count >= max_sends_per_hour:
            return False, "Too many OTP requests. Please wait before requesting again.", 3600

        return True, None, None

    def increment_otp_send_count(self, session_id: str) -> None:
        """Increment OTP send counter and update timestamp."""
        result = self.table("signing_sessions").select(
            "otp_sent_count, otp_last_sent_at"
        ).eq("id", session_id).single().execute()

        now = utc_now()
        current_count = 0

        if result.data:
            last_sent = parse_db_timestamp(result.data.get("otp_last_sent_at"))
            if last_sent:
                # Reset if more than 1 hour
                if (now - last_sent).total_seconds() <= 3600:
                    current_count = result.data.get("otp_sent_count") or 0

        self.table("signing_sessions").update({
            "otp_sent_count": current_count + 1,
            "otp_last_sent_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }).eq("id", session_id).execute()

    def check_otp_verify_limit(
        self,
        session_id: str,
        max_attempts: int = 5,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check OTP verify attempt limit.

        Returns:
            (allowed, error_message)
        """
        result = self.table("signing_sessions").select(
            "otp_verify_attempts, otp_locked_until"
        ).eq("id", session_id).single().execute()

        if not result.data:
            return False, "Session not found"

        data = result.data
        now = utc_now()

        # Check if locked
        locked_until = parse_db_timestamp(data.get("otp_locked_until"))
        if locked_until and locked_until > now:
            return False, "Account temporarily locked. Please try again later."

        attempts = data.get("otp_verify_attempts") or 0
        if attempts >= max_attempts:
            return False, "Too many failed attempts. Please request a new code."

        return True, None

    def increment_otp_verify_attempts(self, session_id: str, lock_after: int = 5) -> None:
        """Increment verify attempts and lock if exceeded."""
        result = self.table("signing_sessions").select(
            "otp_verify_attempts"
        ).eq("id", session_id).single().execute()

        current_attempts = (result.data.get("otp_verify_attempts") or 0) if result.data else 0
        new_attempts = current_attempts + 1
        now = utc_now()

        updates = {
            "otp_verify_attempts": new_attempts,
            "updated_at": now.isoformat(),
        }

        # Lock for 15 minutes if max attempts exceeded
        if new_attempts >= lock_after:
            updates["otp_locked_until"] = (now + timedelta(minutes=15)).isoformat()

        self.table("signing_sessions").update(updates).eq("id", session_id).execute()

    def reset_otp_verify_attempts(self, session_id: str) -> None:
        """Reset verify attempts after successful verification."""
        self.table("signing_sessions").update({
            "otp_verify_attempts": 0,
            "otp_locked_until": None,
            "updated_at": utc_now().isoformat(),
        }).eq("id", session_id).execute()

    # Event operations
    async def create_event(
        self,
        document_id: str,
        workspace_id: str,
        event_type: EventType,
        user_id: Optional[str] = None,
        signer_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> DocumentEvent:
        """
        Create a document event for audit trail using a direct HTTP request
        to ensure user's JWT is forwarded correctly for RLS.
        """
        event_data = {
            "document_id": document_id,
            "workspace_id": workspace_id,
            "event_type": event_type.value,
            "user_id": user_id,
            "signer_id": signer_id,
            "ip_address": ip_address,
            "user_agent": user_agent[:500] if user_agent else None,
            "metadata": metadata or {},
            "created_at": utc_now().isoformat(),
        }

        user_token = get_user_token()

        # Use admin proxy when no user token (admin secret auth)
        if not user_token:
            try:
                result_data = await self.admin_insert("document_events", event_data)
                logger.info(f"Created event {event_type.value} for document {document_id} via admin-proxy")
                return DocumentEvent(**result_data)
            except Exception as e:
                logger.error(f"Error creating event via admin-proxy: {e}")
                raise e

        headers = {
            "apikey": self.settings.supabase_anon_key,
            "Prefer": "return=representation",
            "Authorization": f"Bearer {user_token}",
        }

        url = "/rest/v1/document_events"

        try:
            response = await self._http_client.post(url, headers=headers, json=event_data)
            response.raise_for_status()
            result_data = response.json()

            if not result_data:
                raise Exception("Failed to create event: No data returned from Supabase.")

            logger.info(f"Created event {event_type.value} for document {document_id}")
            return DocumentEvent(**result_data[0])

        except httpx.HTTPStatusError as e:
            logger.error(f"Error creating event: {e.response.status_code} - {e.response.text}")
            raise e
        except Exception as e:
            logger.error(f"An unexpected error occurred while creating an event: {e}")
            raise e

    def get_events(
        self,
        document_id: str,
        workspace_id: str,
    ) -> List[DocumentEvent]:
        """Get all events for a document."""
        result = self.table("document_events").select("*").eq(
            "document_id", document_id
        ).eq(
            "workspace_id", workspace_id
        ).order("created_at").execute()

        return [DocumentEvent(**e) for e in (result.data or [])]

    # Helper methods
    async def check_all_signed(self, document_id: str) -> bool:
        """Check if all signers have signed the document."""
        return await self.get_pending_signers_count(document_id) == 0

    async def get_pending_signers_count(self, document_id: str) -> int:
        """Get count of signers who haven't signed yet (async admin version)."""
        result = await self.admin_select(
            "document_signers",
            {
                "document_id": document_id,
                "status": ("neq", SignerStatus.SIGNED.value)
            },
            single=False
        )
        return len(result) if result else 0

    def get_pending_signers_count_sync(self, document_id: str) -> int:
        """Get count of signers who haven't signed yet (sync version)."""
        result = self.table("document_signers").select(
            "id", count="exact"
        ).eq(
            "document_id", document_id
        ).neq(
            "status", SignerStatus.SIGNED.value
        ).execute()

        return result.count or 0

    def get_signer_details_for_evidence(
        self,
        document_id: str,
    ) -> List[Dict]:
        """
        Get detailed signer information for evidence report.
        Includes OTP channel used, timestamps, etc.
        """
        result = self.table("document_signers").select(
            "id, name, email, phone, status, viewed_at, signed_at, "
            "signing_sessions(otp_channel, otp_verified_at, ip_address, user_agent)"
        ).eq(
            "document_id", document_id
        ).order("order").execute()

        return result.data or []

    async def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get user by ID from auth.users table."""
        # Note: The table name for Supabase's auth users is 'users' in the 'auth' schema.
        # The admin proxy needs to be configured to handle this.
        # Assuming the proxy can handle `auth.users` as a table name.
        result = await self.admin_select(
            "users",
            {"id": user_id},
            single=True,
        )
        return result

    async def get_users_by_ids(self, user_ids: List[str]) -> Dict[str, Dict]:
        """
        Get multiple users by IDs (batch lookup).
        Returns dict mapping user_id -> user_data for efficient lookup.
        """
        if not user_ids:
            return {}

        # Deduplicate IDs
        unique_ids = list(set(user_ids))

        # Query using IN filter via admin proxy
        # Build query with in operator
        url = f"/functions/v1/admin-proxy/users?id=in.({','.join(unique_ids)})"
        headers = {
            "Content-Type": "application/json",
            "X-Admin-Secret": self.settings.admin_api_secret,
        }

        try:
            response = await self._http_client.get(url, headers=headers)
            response.raise_for_status()
            result = response.json()

            # Handle response format
            users_list = result
            if isinstance(result, dict) and "data" in result:
                users_list = result["data"]

            # Build lookup dict
            return {user["id"]: user for user in (users_list or [])}
        except Exception as e:
            logger.warning(f"get_users_by_ids failed: {e}")
            return {}

    # Workspace membership operations
    def get_user_workspace_memberships(self, user_id: str) -> List[Dict]:
        """
        Get all workspace memberships for a user.
        Returns list of {workspace_id, role, ...} ordered by created_at.
        """
        result = self.table("workspace_members").select(
            "workspace_id, role, created_at"
        ).eq(
            "user_id", user_id
        ).order("created_at").execute()

        return result.data or []

    def check_workspace_membership(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Optional[Dict]:
        """
        Check if user is a member of the given workspace.
        Returns membership record with role if member, None otherwise.
        """
        result = self.table("workspace_members").select(
            "workspace_id, role, created_at"
        ).eq(
            "user_id", user_id
        ).eq(
            "workspace_id", workspace_id
        ).maybeSingle().execute()

        return result.data

    def get_user_default_workspace(self, user_id: str) -> Optional[str]:
        """
        Get user's default workspace (first membership by created_at).
        Returns workspace_id or None if user has no memberships.
        """
        memberships = self.get_user_workspace_memberships(user_id)
        if memberships:
            return memberships[0]["workspace_id"]
        return None



# Singleton instance
_supabase_client: Optional[SupabaseClient] = None


def get_supabase_client() -> SupabaseClient:
    """Get the Supabase client singleton."""
    global _supabase_client
    if _supabase_client is None:
        _supabase_client = SupabaseClient()
    return _supabase_client
