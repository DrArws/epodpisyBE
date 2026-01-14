"""
Authentication module for Google ID Token verification.
Handles both authenticated users (Google ID Token) and signing sessions (magic link tokens).
"""
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone

# Use Google's libraries for token verification
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests

from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import get_settings, Settings
from app.models import AuthenticatedUser, SigningSession
from app.utils.security import hash_signing_token
from app.utils.logging import set_context
from app.supabase_client import SupabaseClient, get_supabase_client # Added this import

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)


class AuthenticationError(HTTPException):
    """Custom authentication error."""
    def __init__(self, message: str, code: str = "AUTH_ERROR"):
        super().__init__(
            status_code=401,
            detail={"code": code, "message": message}
        )


class AuthorizationError(HTTPException):
    """Custom authorization error."""
    def __init__(self, message: str, code: str = "FORBIDDEN"):
        super().__init__(
            status_code=403,
            detail={"code": code, "message": message}
        )


class NoWorkspaceError(HTTPException):
    """Error when workspace ID is not provided."""
    def __init__(self, message: str = "Workspace ID is required"):
        super().__init__(
            status_code=400,
            detail={"code": "NO_WORKSPACE", "message": message}
        )


def get_internal_user_id(supabase: SupabaseClient, payload: Dict[str, Any]) -> str:
    """
    Calls a Supabase RPC function to get or create an internal user ID.
    """
    google_sub = payload.get("sub")
    if not google_sub:
        raise HTTPException(status_code=400, detail="Google sub not found in token payload.")

    params = {
        "p_google_sub": google_sub,
        "p_email": payload.get("email"),
        "p_name": payload.get("name"),
        "p_picture": payload.get("picture"),
    }
    
    result = supabase.client.rpc("get_or_create_user_for_google_sub", params).execute()

    if not result.data:
        logger.error(f"Failed to get or create user for Google sub {google_sub}.")
        raise HTTPException(status_code=500, detail="Could not get or create user.")

    # RPC returns TABLE(user_id UUID), so access the user_id column
    return result.data[0]["user_id"]
    

async def verify_google_id_token(
    token: str, settings: Settings = Depends(get_settings)
) -> dict:
    """
    Verifies a Google ID Token against Google's public keys.
    Returns the decoded payload if valid.
    """
    try:
        # The audience should be the OAuth Client ID for the application.
        # This ensures the token was intended for this specific application.
        audience = settings.oauth_client_id
        if not audience:
            logger.error("OAUTH_CLIENT_ID is not configured.")
            raise AuthenticationError(
                "Authentication is not configured correctly.", "AUTH_CONFIG_ERROR"
            )

        payload = google_id_token.verify_oauth2_token(
            token, google_requests.Request(), audience=audience
        )
        return payload

    except ValueError as e:
        # This error is raised by the library for invalid tokens (bad format, expired, wrong aud, etc.)
        logger.error(f"Google ID token verification failed: {e}")
        raise AuthenticationError("Invalid or expired token", "INVALID_TOKEN")
    except Exception as e:
        logger.error(f"Unexpected error during token verification: {e}")
        raise AuthenticationError("Authentication service error", "AUTH_SERVICE_ERROR")


def get_workspace_from_request(request: Request) -> str:
    """
    Get workspace_id from request headers or query parameters.

    Priority:
    1. X-Workspace-ID header
    2. workspace_id query parameter

    Raises NoWorkspaceError if not provided.
    """
    path = request.url.path
    # Check header first
    workspace_id = request.headers.get("X-Workspace-ID")
    if workspace_id:
        logger.info(f"Workspace ID starting with '{workspace_id[:8]}' retrieved from header for path '{path}'.")
        return workspace_id

    # Check query parameter
    workspace_id = request.query_params.get("workspace_id")
    if workspace_id:
        logger.info(f"Workspace ID starting with '{workspace_id[:8]}' retrieved from query parameter for path '{path}'.")
        return workspace_id
    
    logger.warning(f"No workspace ID found in header or query parameters for path '{path}'.")
    raise NoWorkspaceError("X-Workspace-ID header or workspace_id parameter is required")


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    settings: Settings = Depends(get_settings),
    supabase: SupabaseClient = Depends(get_supabase_client),
) -> AuthenticatedUser:
    """
    Dependency that extracts and validates the current user from a Google ID Token
    or from X-User-ID header when X-Admin-Secret is provided.
    """
    # Check for admin secret + X-User-ID pattern (Edge Function calls)
    admin_secret = request.headers.get("X-Admin-Secret")
    if admin_secret:
        await verify_admin_secret(request, settings)
        user_id_header = request.headers.get("X-User-ID")
        if user_id_header:
            # Trust the X-User-ID from authenticated Edge Function
            workspace_id = get_workspace_from_request(request)

            user = AuthenticatedUser(
                user_id=user_id_header,
                internal_user_id=user_id_header,
                workspace_id=workspace_id,
                email=request.headers.get("X-User-Email"),
                name=request.headers.get("X-User-Name"),
                role="member",
            )

            logger.info(f"Edge Function call with X-User-ID: {user_id_header[:8]}...")
            set_context(user_id=user.user_id, workspace_id=user.workspace_id)
            return user

    # Fall back to Google ID Token authentication
    if not credentials:
        raise AuthenticationError("Authorization header required", "MISSING_AUTH")

    token = credentials.credentials

    # Verify Google ID Token
    payload = await verify_google_id_token(token, settings)

    user_id = payload.get("sub")  # 'sub' is the standard claim for user ID
    email = payload.get("email")
    if not user_id or not email:
        raise AuthenticationError("Invalid token: missing user ID or email", "INVALID_TOKEN")

    # Get the internal Supabase UUID via RPC call
    internal_user_id = get_internal_user_id(supabase, payload)

    # Get workspace from request (trusted - no DB verification)
    workspace_id = get_workspace_from_request(request)

    # Assuming a verified Google user has a 'member' role by default.
    user = AuthenticatedUser(
        user_id=user_id,
        internal_user_id=internal_user_id,
        workspace_id=workspace_id,
        email=email,
        name=payload.get("name"),
        picture=payload.get("picture"),
        role="member",
    )

    # Set logging context
    set_context(user_id=user.user_id, workspace_id=user.workspace_id)

    return user


async def get_signing_session_from_token(
    token: str,
    request: Request,
    settings: Settings = Depends(get_settings),
) -> SigningSession:
    """
    Validate a signing session token and return the session.
    Token is validated by comparing hash with stored hash in Supabase.

    Returns proper errors instead of 500:
    - Invalid/not found token: AuthenticationError (404)
    - Expired session: AuthenticationError (410)
    - Already signed: AuthorizationError (409)
    """
    from app.supabase_client import get_supabase_client
    from app.utils.logging import fingerprint, set_context

    token_hash = hash_signing_token(token)
    token_fp = fingerprint(token)
    hash_fp = token_hash[:8]

    # Set context for correlation (no PII)
    set_context(token_fp=token_fp)
    logger.info(f"session_get: token_fp={token_fp}, hash_fp={hash_fp}")

    supabase = get_supabase_client()

    # Find session by token hash via admin proxy (bypasses RLS for public endpoint)
    try:
        session_data = await supabase.get_signing_session_admin(token_hash)
        logger.info(f"session_get: result={'FOUND' if session_data else 'NOT_FOUND'}")
    except Exception as e:
        # Log the error but return user-friendly message
        logger.warning(f"Database error looking up signing session: {e}")
        raise AuthenticationError("Invalid signing token", "INVALID_SIGNING_TOKEN")

    if not session_data:
        logger.warning(f"session_get: not_found, token_fp={token_fp}")
        raise AuthenticationError("Invalid signing token", "INVALID_SIGNING_TOKEN")

    signer_data = session_data.get("document_signers", {})

    # Check if session is expired
    expires_at = session_data.get("expires_at")
    if expires_at:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        # Ensure timezone-aware comparison (handle both naive and aware datetimes)
        now_utc = datetime.now(timezone.utc)
        if expiry.tzinfo is None:
            # Naive datetime - assume it's UTC
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry < now_utc:
            raise AuthenticationError("Signing link has expired", "SESSION_EXPIRED")

    # Check if already signed
    if signer_data.get("status") == "signed":
        raise AuthorizationError("Document already signed", "ALREADY_SIGNED")

    session = SigningSession(
        id=session_data["id"],
        document_id=session_data["document_id"],
        signer_id=session_data["signer_id"],
        workspace_id=session_data["workspace_id"],
        token_hash=token_hash,
        phone=signer_data.get("phone"),
        email=signer_data.get("email"),
        name=signer_data.get("name", "Unknown"),
        status=signer_data.get("status", "pending"),
        verification_method=signer_data.get("verification"),  # "none", "sms", "whatsapp" (DB column is "verification")
        otp_verified_at=session_data.get("otp_verified_at"),
        signed_at=signer_data.get("signed_at"),
        viewed_at=signer_data.get("viewed_at"),
    )

    # Update IP and user agent
    session.ip_address = get_client_ip(request)
    session.user_agent = request.headers.get("User-Agent", "")[:500]

    # Set logging context
    set_context(
        document_id=session.document_id,
        signer_id=session.signer_id,
        workspace_id=session.workspace_id,
    )

    return session


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address, handling proxies and Cloud Run.
    """
    # Cloud Run / load balancer headers
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()

    # Real IP header (some proxies)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Direct connection
    if request.client:
        return request.client.host

    return "unknown"


async def verify_workspace_access(
    user: AuthenticatedUser,
    document_workspace_id: str,
) -> None:
    """
    Verify that user has access to the given workspace.
    Raises AuthorizationError if not.
    """
    if user.workspace_id != document_workspace_id:
        raise AuthorizationError(
            "You don't have access to this resource",
            "WORKSPACE_MISMATCH"
        )


import secrets as secrets_module


async def verify_admin_secret(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> bool:
    """
    Verify admin API secret from X-Admin-Secret header.
    Used for Edge Function → Cloud Run communication.
    """
    admin_secret = request.headers.get("X-Admin-Secret")

    if not admin_secret:
        raise AuthenticationError(
            "Admin secret required",
            "MISSING_ADMIN_SECRET"
        )

    if not settings.admin_api_secret:
        logger.error("ADMIN_API_SECRET not configured")
        raise AuthenticationError(
            "Admin authentication not configured",
            "ADMIN_NOT_CONFIGURED"
        )

    # Constant-time comparison to prevent timing attacks
    if not secrets_module.compare_digest(admin_secret, settings.admin_api_secret):
        raise AuthenticationError(
            "Invalid admin secret",
            "INVALID_ADMIN_SECRET"
        )

    return True


async def get_admin_or_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    settings: Settings = Depends(get_settings),
    supabase: SupabaseClient = Depends(get_supabase_client),
) -> AuthenticatedUser:
    """
    Dependency that allows admin secret OR a user's Google ID Token.
    - For Edge Functions: Send X-Admin-Secret + X-User-ID header. The function is trusted.
    - For direct frontend calls: Send Google ID Token in Authorization header.
    """
    admin_secret = request.headers.get("X-Admin-Secret")
    is_admin_call = False

    if admin_secret:
        # Verify admin secret first
        await verify_admin_secret(request, settings)
        is_admin_call = True

        # When admin secret is valid, check for X-User-ID header
        user_id_header = request.headers.get("X-User-ID")
        if user_id_header:
            # Trust the X-User-ID from authenticated Edge Function
            workspace_id = get_workspace_from_request(request)

            user = AuthenticatedUser(
                user_id=user_id_header,  # Use header value as user_id
                internal_user_id=user_id_header,  # Same as user_id for admin calls
                workspace_id=workspace_id,
                email=request.headers.get("X-User-Email"),  # Optional
                name=request.headers.get("X-User-Name"),  # Optional
                role="admin",
            )

            logger.info(f"Admin call with X-User-ID: {user_id_header[:8]}...")
            set_context(user_id=user.user_id, workspace_id=user.workspace_id)
            return user

    # Fall back to Google ID Token authentication
    if not credentials:
        raise AuthenticationError("Authorization header required", "MISSING_AUTH")

    token = credentials.credentials
    payload = await verify_google_id_token(token, settings)

    user_id = payload.get("sub")
    email = payload.get("email")
    if not user_id or not email:
        raise AuthenticationError("Invalid token: missing user ID or email", "INVALID_TOKEN")

    # Get the internal Supabase UUID via RPC call
    internal_user_id = get_internal_user_id(supabase, payload)

    workspace_id = get_workspace_from_request(request)

    # If the call was authenticated via admin secret, grant admin role.
    role = "admin" if is_admin_call else "member"

    user = AuthenticatedUser(
        user_id=user_id,
        internal_user_id=internal_user_id,
        workspace_id=workspace_id,
        email=email,
        name=payload.get("name"),
        picture=payload.get("picture"),
        role=role,
    )

    set_context(user_id=user.user_id, workspace_id=user.workspace_id)
    return user
