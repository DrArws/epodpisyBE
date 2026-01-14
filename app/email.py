"""
Email module using Resend for sending emails.
Templates are rendered via Supabase Edge Function render-email-template.

Includes reliable delivery with retry logic and audit logging.
"""
import asyncio
import hashlib
import logging
from enum import Enum
from typing import Optional, Dict, Any, Callable, Awaitable, List, TYPE_CHECKING

if TYPE_CHECKING:
    pass  # Future type imports
from dataclasses import dataclass, field

import httpx

from app.config import get_settings, Settings
from app.models import EmailTemplateType, EmailTemplateContext

logger = logging.getLogger(__name__)


# Retry configuration
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAYS_SECONDS = [0, 2, 4]  # Exponential backoff: immediate, 2s, 4s


class EmailDeliveryStatus(str, Enum):
    """Email delivery status for tracking."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"  # Email not configured or disabled


@dataclass
class EmailAttempt:
    """Record of a single email send attempt."""
    attempt_number: int
    success: bool
    error: Optional[str] = None
    message_id: Optional[str] = None


# Type alias for audit callback
AuditCallback = Callable[[str, str, Dict[str, Any]], Awaitable[None]]


@dataclass
class EmailResult:
    """Result of email send operation with delivery tracking."""
    success: bool
    message_id: Optional[str] = None
    error: Optional[str] = None
    delivery_status: EmailDeliveryStatus = EmailDeliveryStatus.PENDING
    attempts: List[EmailAttempt] = field(default_factory=list)
    total_attempts: int = 0

    @property
    def is_delivered(self) -> bool:
        """Check if email was successfully delivered."""
        return self.delivery_status == EmailDeliveryStatus.SENT

    @property
    def is_failed(self) -> bool:
        """Check if all delivery attempts failed."""
        return self.delivery_status == EmailDeliveryStatus.FAILED


@dataclass
class RenderedEmail:
    """Rendered email ready to send."""
    subject: str
    html: str
    text: Optional[str] = None


class EmailService:
    """Email service using Resend HTTP API with Edge Function template rendering."""

    RESEND_API_URL = "https://api.resend.com/emails"

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

    def is_configured(self) -> bool:
        """Check if email service is properly configured."""
        return bool(self.settings.resend_api_key)

    async def render_template(
        self,
        workspace_id: str,
        template_type: EmailTemplateType,
        context: EmailTemplateContext,
        http_client: httpx.AsyncClient,
    ) -> RenderedEmail:
        """
        Render email template via Edge Function.
        POST /functions/v1/render-email-template
        """
        url = f"{self.settings.supabase_url}/functions/v1/render-email-template"
        headers = {
            "Content-Type": "application/json",
            "X-Admin-Secret": self.settings.admin_api_secret,
        }
        context_dict = context.model_dump(exclude_none=True)
        payload = {
            "workspace_id": workspace_id,
            "template_type": template_type.value,
            "context": context_dict,
        }

        # Debug: log what we're sending to Edge Function
        logger.info(f"Rendering template {template_type.value} with context keys: {list(context_dict.keys())}")
        if "sign_url" in context_dict:
            logger.info(f"sign_url value: {context_dict['sign_url'][:50]}...")
        if "signing_link" in context_dict:
            logger.info(f"signing_link value: {context_dict['signing_link'][:50]}...")

        try:
            response = await http_client.post(url, headers=headers, json=payload, timeout=30.0)
            response.raise_for_status()
            data = response.json()

            return RenderedEmail(
                subject=data["subject"],
                html=data["html"],
                text=data.get("text"),
            )

        except httpx.HTTPStatusError as e:
            logger.error(f"Edge function error {e.response.status_code}: {e.response.text}")
            raise ValueError(f"Template rendering failed: {e.response.text}")
        except Exception as e:
            logger.error(f"Failed to render template: {e}")
            raise ValueError(f"Template rendering failed: {e}")

    async def send_email(
        self,
        to_email: str,
        subject: str,
        html: str,
        text: Optional[str] = None,
        audit_callback: Optional[AuditCallback] = None,
        context_id: Optional[str] = None,  # Document ID or similar for audit
    ) -> EmailResult:
        """
        Send email via Resend HTTP API with retry logic.

        Implements reliable delivery:
        - 3 attempts with exponential backoff (0s, 2s, 4s)
        - Audit logging via optional callback
        - Detailed attempt tracking

        Args:
            to_email: Recipient email address
            subject: Email subject
            html: HTML content
            text: Optional plain text content
            audit_callback: Optional async callback for audit logging
            context_id: Optional ID for audit context (e.g., document_id)

        Returns:
            EmailResult with delivery_status and attempt history
        """
        # Fingerprint for logging (no PII)
        email_fp = hashlib.sha256(to_email.encode()).hexdigest()[:8]

        if not self.is_configured():
            logger.warning(f"Resend API key not configured, skipping email to {email_fp}")
            return EmailResult(
                success=False,
                error="Email service not configured",
                delivery_status=EmailDeliveryStatus.SKIPPED,
            )

        payload = {
            "from": f"Podpisy <{self.settings.resend_from_email}>",
            "to": [to_email],
            "subject": subject,
            "html": html,
        }
        if text:
            payload["text"] = text

        headers = {
            "Authorization": f"Bearer {self.settings.resend_api_key}",
            "Content-Type": "application/json",
        }

        attempts: List[EmailAttempt] = []
        last_error: Optional[str] = None
        message_id: Optional[str] = None

        for attempt_num in range(1, MAX_RETRY_ATTEMPTS + 1):
            # Wait before retry (skip delay for first attempt)
            if attempt_num > 1:
                delay = RETRY_DELAYS_SECONDS[attempt_num - 1] if attempt_num - 1 < len(RETRY_DELAYS_SECONDS) else 4
                logger.info(f"Email retry {attempt_num}/{MAX_RETRY_ATTEMPTS} to {email_fp}, waiting {delay}s")
                await asyncio.sleep(delay)

            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        self.RESEND_API_URL,
                        json=payload,
                        headers=headers,
                        timeout=30.0,
                    )

                    if response.status_code in (200, 201):
                        data = response.json()
                        message_id = data.get("id")

                        attempt = EmailAttempt(
                            attempt_number=attempt_num,
                            success=True,
                            message_id=message_id,
                        )
                        attempts.append(attempt)

                        logger.info(
                            f"Email sent to {email_fp} on attempt {attempt_num}, "
                            f"message_id: {message_id}"
                        )

                        # Audit callback for success
                        if audit_callback and context_id:
                            try:
                                await audit_callback("EMAIL_SENT", context_id, {
                                    "email_fp": email_fp,
                                    "message_id": message_id,
                                    "attempt": attempt_num,
                                })
                            except Exception as e:
                                logger.warning(f"Audit callback failed: {e}")

                        return EmailResult(
                            success=True,
                            message_id=message_id,
                            delivery_status=EmailDeliveryStatus.SENT,
                            attempts=attempts,
                            total_attempts=attempt_num,
                        )
                    else:
                        last_error = f"API error {response.status_code}: {response.text[:200]}"
                        attempt = EmailAttempt(
                            attempt_number=attempt_num,
                            success=False,
                            error=last_error,
                        )
                        attempts.append(attempt)
                        logger.warning(
                            f"Email attempt {attempt_num}/{MAX_RETRY_ATTEMPTS} to {email_fp} "
                            f"failed: {last_error}"
                        )

            except httpx.TimeoutException as e:
                last_error = f"Timeout: {e}"
                attempt = EmailAttempt(
                    attempt_number=attempt_num,
                    success=False,
                    error=last_error,
                )
                attempts.append(attempt)
                logger.warning(
                    f"Email attempt {attempt_num}/{MAX_RETRY_ATTEMPTS} to {email_fp} "
                    f"timed out"
                )

            except Exception as e:
                last_error = str(e)
                attempt = EmailAttempt(
                    attempt_number=attempt_num,
                    success=False,
                    error=last_error,
                )
                attempts.append(attempt)
                logger.warning(
                    f"Email attempt {attempt_num}/{MAX_RETRY_ATTEMPTS} to {email_fp} "
                    f"failed: {last_error}"
                )

        # All attempts failed
        logger.error(
            f"Email to {email_fp} failed after {MAX_RETRY_ATTEMPTS} attempts. "
            f"Last error: {last_error}"
        )

        # Audit callback for failure
        if audit_callback and context_id:
            try:
                await audit_callback("EMAIL_FAILED", context_id, {
                    "email_fp": email_fp,
                    "total_attempts": MAX_RETRY_ATTEMPTS,
                    "last_error": last_error[:200] if last_error else "Unknown",
                })
            except Exception as e:
                logger.warning(f"Audit callback failed: {e}")

        return EmailResult(
            success=False,
            error=last_error,
            delivery_status=EmailDeliveryStatus.FAILED,
            attempts=attempts,
            total_attempts=MAX_RETRY_ATTEMPTS,
        )

    async def _send_templated_email(
        self,
        template_type: EmailTemplateType,
        to_email: str,
        context: EmailTemplateContext,
        workspace_id: str,
        http_client: httpx.AsyncClient,
        subject_prefix: str = "",
        audit_callback: Optional[AuditCallback] = None,
        context_id: Optional[str] = None,
    ) -> EmailResult:
        """Generic method to render template via Edge Function and send email."""
        # Render via Edge Function
        rendered = await self.render_template(
            workspace_id=workspace_id,
            template_type=template_type,
            context=context,
            http_client=http_client,
        )

        # Apply subject prefix if provided (e.g., "[TEST]")
        subject = f"{subject_prefix}{rendered.subject}" if subject_prefix else rendered.subject

        # Send via Resend with retry logic
        return await self.send_email(
            to_email=to_email,
            subject=subject,
            html=rendered.html,
            text=rendered.text,
            audit_callback=audit_callback,
            context_id=context_id,
        )

    async def send_signing_invitation(
        self,
        to_email: str,
        context: EmailTemplateContext,
        workspace_id: str,
        http_client: httpx.AsyncClient,
        audit_callback: Optional[AuditCallback] = None,
        document_id: Optional[str] = None,
    ) -> EmailResult:
        """
        Send DOCUMENT_SEND email - initial signing request.

        Args:
            to_email: Recipient email
            context: Template context (document_name, workspace_name, signer_name, signing_link, etc.)
            workspace_id: Workspace ID
            http_client: HTTP client for Edge Function
            audit_callback: Optional callback for audit logging
            document_id: Document ID for audit context

        Returns:
            EmailResult with delivery status and attempt history
        """
        return await self._send_templated_email(
            EmailTemplateType.DOCUMENT_SEND,
            to_email,
            context,
            workspace_id,
            http_client,
            audit_callback=audit_callback,
            context_id=document_id,
        )

    async def send_reminder(
        self,
        to_email: str,
        context: EmailTemplateContext,
        workspace_id: str,
        http_client: httpx.AsyncClient,
        audit_callback: Optional[AuditCallback] = None,
        document_id: Optional[str] = None,
    ) -> EmailResult:
        """
        Send REMINDER email - reminder to sign.
        Context: document_name, workspace_name, signer_name, signing_link, expires_at, message?
        """
        return await self._send_templated_email(
            EmailTemplateType.REMINDER,
            to_email,
            context,
            workspace_id,
            http_client,
            audit_callback=audit_callback,
            context_id=document_id,
        )

    async def send_signed_notification(
        self,
        to_email: str,
        context: EmailTemplateContext,
        workspace_id: str,
        http_client: httpx.AsyncClient,
        audit_callback: Optional[AuditCallback] = None,
        document_id: Optional[str] = None,
    ) -> EmailResult:
        """
        Send DOCUMENT_SIGNED email - notification that someone signed.
        Context: document_name, workspace_name, signer_name, signed_at
        """
        return await self._send_templated_email(
            EmailTemplateType.DOCUMENT_SIGNED,
            to_email,
            context,
            workspace_id,
            http_client,
            audit_callback=audit_callback,
            context_id=document_id,
        )

    async def send_all_signed_notification(
        self,
        to_email: str,
        context: EmailTemplateContext,
        workspace_id: str,
        http_client: httpx.AsyncClient,
        audit_callback: Optional[AuditCallback] = None,
        document_id: Optional[str] = None,
    ) -> EmailResult:
        """
        Send ALL_SIGNED email - all signatures complete.
        Context: document_name, workspace_name, completed_at, download_link?
        """
        return await self._send_templated_email(
            EmailTemplateType.ALL_SIGNED,
            to_email,
            context,
            workspace_id,
            http_client,
            audit_callback=audit_callback,
            context_id=document_id,
        )

    async def send_test_email(
        self,
        to_email: str,
        template_type: EmailTemplateType,
        context: EmailTemplateContext,
        workspace_id: str,
        http_client: httpx.AsyncClient,
    ) -> EmailResult:
        """
        Send test email with [TEST] prefix in subject.
        No retry audit for test emails.
        """
        return await self._send_templated_email(
            template_type,
            to_email,
            context,
            workspace_id,
            http_client,
            subject_prefix="[TEST] ",
        )


# Singleton instance
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get the email service singleton."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service


def create_audit_callback(supabase_client: Any, workspace_id: str) -> AuditCallback:
    """
    Create an audit callback that logs email events to document_events.

    Usage:
        audit_cb = create_audit_callback(supabase, workspace_id)
        result = await email_service.send_signing_invitation(
            ...,
            audit_callback=audit_cb,
            document_id=document_id,
        )

    Note: This is a placeholder implementation. For production use,
    consider adding EMAIL_SENT and EMAIL_FAILED to EventType enum
    and the DB constraint.
    """
    async def callback(event_type: str, context_id: str, metadata: Dict[str, Any]) -> None:
        """Log email event to audit trail."""
        logger.info(
            f"Email audit: type={event_type}, context_id={context_id}, "
            f"metadata={metadata}"
        )
        # TODO: When EMAIL_SENT/EMAIL_FAILED are added to EventType enum and DB:
        # await supabase_client.create_event(
        #     document_id=context_id,
        #     workspace_id=workspace_id,
        #     event_type=EventType[event_type],
        #     metadata=metadata,
        # )

    return callback


# Manual retry instructions for failed emails
RETRY_INSTRUCTIONS = """
## Manual Email Retry Instructions

When emails fail after all retry attempts, they are logged with delivery_status='failed'.

To manually retry failed emails:

1. Query failed deliveries from logs:
   SELECT * FROM document_events
   WHERE event_type = 'EMAIL_FAILED'
   AND created_at > NOW() - INTERVAL '24 hours';

2. Use the admin API to resend:
   POST /v1/admin/resend-email
   {
       "document_id": "<document_id>",
       "signer_id": "<signer_id>",
       "template_type": "DOCUMENT_SEND"
   }

3. Or use send_document endpoint with dry_run=false for that signer.

Future: Implement automated retry job that processes EMAIL_FAILED events.
"""


__all__ = [
    "EmailService",
    "EmailResult",
    "EmailDeliveryStatus",
    "EmailAttempt",
    "RenderedEmail",
    "AuditCallback",
    "get_email_service",
    "create_audit_callback",
    "MAX_RETRY_ATTEMPTS",
    "RETRY_DELAYS_SECONDS",
]
