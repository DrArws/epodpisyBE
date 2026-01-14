"""
Logging configuration with request_id correlation.
Structured logging for Cloud Logging compatibility.

PII Protection:
- Never log raw tokens, salts, emails, phones, or signatures
- Use fingerprints (sha256[:8]) for correlation
- All PII fields must go through fingerprint() helper
"""
import hashlib
import logging
import sys
import uuid
import json
from contextvars import ContextVar
from typing import Optional
from datetime import datetime

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


def fingerprint(value: Optional[str], prefix: str = "") -> str:
    """
    Create a safe fingerprint for logging PII values.

    Args:
        value: The sensitive value to fingerprint (token, email, phone, etc.)
        prefix: Optional prefix for the fingerprint (e.g., "tok_", "email_")

    Returns:
        8-char hex fingerprint with optional prefix, or "none" if value is None/empty

    Example:
        fingerprint("secret_token_123", "tok_") -> "tok_a1b2c3d4"
        fingerprint("user@example.com", "email_") -> "email_f5e6d7c8"
    """
    if not value:
        return f"{prefix}none" if prefix else "none"
    fp = hashlib.sha256(value.encode()).hexdigest()[:8]
    return f"{prefix}{fp}" if prefix else fp


def mask_email(email: Optional[str]) -> str:
    """Mask email for safe logging: john@example.com -> j***@e***.com"""
    if not email or "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    domain_parts = domain.split(".")
    masked_local = local[0] + "***" if local else "***"
    masked_domain = domain_parts[0][0] + "***" if domain_parts[0] else "***"
    return f"{masked_local}@{masked_domain}.{domain_parts[-1] if len(domain_parts) > 1 else 'com'}"


def mask_phone(phone: Optional[str]) -> str:
    """Mask phone for safe logging: +420123456789 -> ***6789"""
    if not phone:
        return "***"
    return "***" + phone[-4:] if len(phone) >= 4 else "***"


# Context variables for request correlation
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
document_id_var: ContextVar[Optional[str]] = ContextVar("document_id", default=None)
signer_id_var: ContextVar[Optional[str]] = ContextVar("signer_id", default=None)
user_id_var: ContextVar[Optional[str]] = ContextVar("user_id", default=None)
workspace_id_var: ContextVar[Optional[str]] = ContextVar("workspace_id", default=None)
session_fp_var: ContextVar[Optional[str]] = ContextVar("session_fp", default=None)
token_fp_var: ContextVar[Optional[str]] = ContextVar("token_fp", default=None)


def get_request_id() -> Optional[str]:
    return request_id_var.get()


def set_request_id(request_id: str) -> None:
    request_id_var.set(request_id)


def set_context(
    document_id: Optional[str] = None,
    signer_id: Optional[str] = None,
    user_id: Optional[str] = None,
    workspace_id: Optional[str] = None,
    session_fp: Optional[str] = None,
    token_fp: Optional[str] = None,
) -> None:
    """
    Set logging context variables.

    Args:
        document_id: Document UUID (safe to log)
        signer_id: Signer UUID (safe to log)
        user_id: User UUID (safe to log)
        workspace_id: Workspace UUID (safe to log)
        session_fp: Session fingerprint (already hashed, safe to log)
        token_fp: Token fingerprint (already hashed, safe to log)
    """
    if document_id:
        document_id_var.set(document_id)
    if signer_id:
        signer_id_var.set(signer_id)
    if user_id:
        user_id_var.set(user_id)
    if workspace_id:
        workspace_id_var.set(workspace_id)
    if session_fp:
        session_fp_var.set(session_fp)
    if token_fp:
        token_fp_var.set(token_fp)


def clear_context() -> None:
    """Clear all context variables."""
    request_id_var.set(None)
    document_id_var.set(None)
    signer_id_var.set(None)
    user_id_var.set(None)
    workspace_id_var.set(None)
    session_fp_var.set(None)
    token_fp_var.set(None)


class CloudLoggingFormatter(logging.Formatter):
    """
    Formatter for Google Cloud Logging structured logs.
    Outputs JSON format compatible with Cloud Logging.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "logging.googleapis.com/sourceLocation": {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            },
        }

        # Add correlation IDs if available
        request_id = request_id_var.get()
        if request_id:
            log_entry["logging.googleapis.com/trace"] = request_id
            log_entry["request_id"] = request_id

        document_id = document_id_var.get()
        if document_id:
            log_entry["document_id"] = document_id

        signer_id = signer_id_var.get()
        if signer_id:
            log_entry["signer_id"] = signer_id

        user_id = user_id_var.get()
        if user_id:
            log_entry["user_id"] = user_id

        workspace_id = workspace_id_var.get()
        if workspace_id:
            log_entry["workspace_id"] = workspace_id

        session_fp = session_fp_var.get()
        if session_fp:
            log_entry["session_fp"] = session_fp

        token_fp = token_fp_var.get()
        if token_fp:
            log_entry["token_fp"] = token_fp

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if hasattr(record, "extra_data"):
            log_entry["data"] = record.extra_data

        return json.dumps(log_entry)


class DevelopmentFormatter(logging.Formatter):
    """Human-readable formatter for local development."""

    def format(self, record: logging.LogRecord) -> str:
        request_id = request_id_var.get() or "-"
        document_id = document_id_var.get() or "-"
        session_fp = session_fp_var.get()
        token_fp = token_fp_var.get()

        prefix = f"[{record.levelname}] [{request_id[:8] if request_id != '-' else '-'}]"
        if document_id != "-":
            prefix += f" [doc:{document_id[:8]}]"
        if session_fp:
            prefix += f" [sess:{session_fp}]"
        if token_fp:
            prefix += f" [tok:{token_fp}]"

        return f"{prefix} {record.getMessage()}"


def setup_logging(environment: str = "development", level: int = logging.INFO) -> None:
    """
    Configure logging based on environment.
    - production: JSON structured logs for Cloud Logging
    - development: Human-readable format
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    if environment == "production":
        handler.setFormatter(CloudLoggingFormatter())
    else:
        handler.setFormatter(DevelopmentFormatter())

    root_logger.addHandler(handler)

    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("google").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that assigns a unique request_id to each request.
    Also extracts document_id from path if present.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Get or generate request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        set_request_id(request_id)

        # Extract document_id from path if present
        path_parts = request.url.path.split("/")
        for i, part in enumerate(path_parts):
            if part == "documents" and i + 1 < len(path_parts):
                document_id_var.set(path_parts[i + 1])
                break
            # Handle both URL patterns:
            # - /v1/signing-sessions/{token} (legacy)
            # - /v1/signing/sessions/{token} (new)
            if part == "signing-sessions" and i + 1 < len(path_parts):
                # For signing sessions, we'll set document_id later when we validate the token
                pass
            if part == "sessions" and i > 0 and path_parts[i - 1] == "signing" and i + 1 < len(path_parts):
                # For new signing/sessions pattern, document_id set later when token is validated
                pass

        # Store request_id in request state for easy access
        request.state.request_id = request_id

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            clear_context()


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name."""
    return logging.getLogger(name)
