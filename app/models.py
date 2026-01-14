from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, Field, field_validator
import base64


class BaseRequest(BaseModel):
    """Base class for all request models - ignores extra fields."""
    model_config = ConfigDict(extra="ignore")


# Enums
class OTPChannel(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"


class VerificationMethod(str, Enum):
    """Verification method for signers."""
    NONE = "none"      # No OTP verification required
    SMS = "sms"        # SMS OTP verification
    WHATSAPP = "whatsapp"  # WhatsApp OTP verification
    EMAIL = "email"    # Email verification (future)


class SignerStatus(str, Enum):
    PENDING = "pending"
    VIEWED = "viewed"
    VERIFIED = "verified"
    SIGNED = "signed"
    DECLINED = "declined"


class DocumentStatus(str, Enum):
    DRAFT = "draft"
    SENT = "sent"  # Document sent for signing
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class EventType(str, Enum):
    # Events allowed by DB CHECK constraint (events_type_chk)
    DOCUMENT_CREATED = "DOCUMENT_CREATED"
    DOCUMENT_UPDATED = "DOCUMENT_UPDATED"
    DOCUMENT_CONVERTED_TO_PDF = "DOCUMENT_CONVERTED_TO_PDF"
    SIGNER_ADDED = "SIGNER_ADDED"


class EmailTemplateType(str, Enum):
    DOCUMENT_SEND = "DOCUMENT_SEND"
    REMINDER = "REMINDER"
    DOCUMENT_SIGNED = "DOCUMENT_SIGNED"
    ALL_SIGNED = "ALL_SIGNED"


# Request Models
class UploadUrlRequest(BaseRequest):
    filename: str = Field(..., min_length=1, max_length=255)
    content_type: str = Field(..., min_length=1)

    @field_validator("content_type")
    @classmethod
    def validate_content_type(cls, v: str) -> str:
        # Normalize: lowercase and strip whitespace
        v = v.lower().strip()

        # Allowed types with common browser variations
        allowed_types = {
            # PDF
            "application/pdf",
            # Word documents
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-word",  # Alternative
            # Excel
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/excel",  # Alternative
            "application/x-excel",  # Alternative
            # PowerPoint
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            # OpenDocument
            "application/vnd.oasis.opendocument.text",
            "application/vnd.oasis.opendocument.spreadsheet",
            "application/vnd.oasis.opendocument.presentation",
            # Images - including browser variations
            "image/jpeg",
            "image/jpg",  # Common browser variation
            "image/pjpeg",  # Progressive JPEG
            "image/png",
            "image/gif",
            "image/webp",
            "image/tiff",
            "image/tif",  # Alternative extension
            "image/bmp",
            "image/x-ms-bmp",  # Windows BMP
            # Text
            "text/plain",
            "text/csv",
            "text/tab-separated-values",
            # Rich text
            "application/rtf",
            "text/rtf",
        }

        if v not in allowed_types:
            raise ValueError(f"Unsupported content type: {v}")
        return v


class ConvertToPdfRequest(BaseRequest):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    storage_path: str = Field(..., min_length=1, alias="storage_path")
    filename: str = Field(..., min_length=1, alias="filename")
    content_type: str = Field(..., min_length=1)


class SignerInput(BaseRequest):
    """Signer information for document creation."""
    name: str = Field(..., min_length=1, max_length=200)
    email: Optional[str] = Field(None, max_length=254)
    phone: Optional[str] = Field(None, max_length=20)
    signing_order: int = Field(default=1, ge=1)
    verification: Optional[VerificationMethod] = Field(
        default=None,
        description="Verification method: 'none', 'sms', or 'email'. If not provided, defaults to 'sms' in DB."
    )


class CreateDocumentRequest(BaseRequest):
    """Request to create a new document."""
    name: str = Field(..., min_length=1, max_length=255)
    signers: List[SignerInput] = Field(..., min_length=1)


class SendDocumentRequest(BaseRequest):
    """Request to send document for signing."""
    message: Optional[str] = Field(None, max_length=1000, description="Optional message to signers")
    send_email: bool = Field(default=True, description="Send signing links via email")
    send_sms: bool = Field(default=False, description="Send signing links via SMS")
    dry_run: bool = Field(default=False, description="Create sessions and return URLs without sending messages")


class SendOTPRequest(BaseRequest):
    channel: OTPChannel


class VerifyOTPRequest(BaseRequest):
    code: str = Field(..., min_length=4, max_length=10)

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("OTP code must contain only digits")
        return v


class SignaturePlacement(BaseRequest):
    page: int = Field(..., ge=1, description="1-indexed page number")
    x: float = Field(..., ge=0, description="X coordinate in PDF points from left")
    y: float = Field(..., ge=0, description="Y coordinate in PDF points from bottom")
    w: float = Field(..., gt=0, description="Width in PDF points")
    h: float = Field(..., gt=0, description="Height in PDF points")


class SignRequest(BaseRequest):
    signature_png_base64: str = Field(..., min_length=100)
    placement: SignaturePlacement
    consent: bool = Field(..., description="User must consent to signing")

    @field_validator("signature_png_base64")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        try:
            # Remove data URL prefix if present
            if v.startswith("data:image/png;base64,"):
                v = v[22:]
            # Validate base64
            decoded = base64.b64decode(v)
            # Check PNG magic bytes
            if not decoded[:8] == b'\x89PNG\r\n\x1a\n':
                raise ValueError("Invalid PNG signature")
            return v
        except Exception as e:
            raise ValueError(f"Invalid base64 PNG image: {e}")

    @field_validator("consent")
    @classmethod
    def validate_consent(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Consent is required to sign the document")
        return v


# Response Models
class UploadUrlResponse(BaseModel):
    signed_upload_url: str
    gcs_path: str
    expires_in_seconds: int


class ConvertToPdfResponse(BaseModel):
    pdf_gcs_path: str
    pdf_download_url: str
    page_count: int


class OTPSendResponse(BaseModel):
    success: bool
    channel: OTPChannel
    message: str = "OTP sent successfully"


class OTPVerifyResponse(BaseModel):
    success: bool
    verified: bool
    message: str


class SignResponse(BaseModel):
    success: bool
    signed_pdf_url: Optional[str] = None
    signed_at: datetime
    is_document_complete: bool
    message: str


class FinalizeResponse(BaseModel):
    success: bool
    evidence_report_path: str
    evidence_download_url: str
    document_hash: str
    completed_at: datetime


class SignerResponse(BaseModel):
    """Signer information in response."""
    id: str
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    status: SignerStatus
    signing_order: int
    verification: Optional[str] = None  # 'none', 'sms', or 'email'
    viewed_at: Optional[datetime] = None
    signed_at: Optional[datetime] = None


class AuthorInfo(BaseModel):
    """Author information for document."""
    id: str
    name: str = "Neznámý"
    email: str = ""


class DocumentResponse(BaseModel):
    """Document response model."""
    id: str
    name: str
    status: DocumentStatus
    workspace_id: str
    gcs_pdf_path: Optional[str] = None
    page_count: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    created_by: str
    author: Optional[AuthorInfo] = None
    signers: Optional[List[SignerResponse]] = None


class DocumentListResponse(BaseModel):
    """Response for document list."""
    documents: List[DocumentResponse]
    total: int
    page: int
    page_size: int


class DeliveryStatus(str, Enum):
    """Status of message delivery attempt."""
    NOT_SENT = "not_sent"
    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"  # e.g., no email/phone provided


class DeliveryAttempt(BaseModel):
    """Result of a single delivery attempt (email or SMS)."""
    enabled: bool = False
    status: DeliveryStatus = DeliveryStatus.NOT_SENT
    provider_message_id: Optional[str] = None
    error: Optional[str] = None


class SignerWithLink(BaseModel):
    """Signer with signing link for send response."""
    id: str
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    sign_url: str
    signing_link: Optional[str] = None  # Alias for frontend compatibility
    expires_at: Optional[datetime] = None
    email_delivery: Optional[DeliveryAttempt] = None
    sms_delivery: Optional[DeliveryAttempt] = None


class DeliverySummary(BaseModel):
    """Summary of all delivery attempts."""
    send_email: bool
    send_sms: bool
    dry_run: bool
    emails_sent: int = 0
    emails_failed: int = 0
    sms_sent: int = 0
    sms_failed: int = 0


class SendDocumentResponse(BaseModel):
    """Response after sending document for signing."""
    success: bool
    message: str
    signers: List[SignerWithLink]
    document_id: str
    document_name: str
    delivery: Optional[DeliverySummary] = None


class DownloadLinksResponse(BaseModel):
    """Response with download URLs for document."""
    original_url: Optional[str] = None
    pdf_url: Optional[str] = None
    signed_url: Optional[str] = None
    evidence_url: Optional[str] = None
    expires_in_seconds: int


class PdfUrlResponse(BaseModel):
    """Response for PDF preview URL endpoint."""
    pdf_url: str
    expires_in: int = 600  # seconds


class ValidateSessionResponse(BaseModel):
    """Response for signing session validation."""
    valid: bool
    document_id: Optional[str] = None
    document_name: Optional[str] = None
    signer_name: Optional[str] = None
    signer_email: Optional[str] = None
    signer_status: Optional[SignerStatus] = None
    requires_otp: bool = True
    otp_verified: bool = False
    pdf_download_url: Optional[str] = None
    page_count: Optional[int] = None
    message: str = ""


# Verification Response
class VerifyResponse(BaseModel):
    """Response from /v1/verify endpoint."""
    valid: bool
    verification_id: str
    document_id: Optional[str] = None
    signer_name: Optional[str] = None
    signed_at: Optional[datetime] = None
    verification_method: Optional[str] = None
    # NOTE: expected_hash intentionally not exposed - use POST /hash to verify
    status: str = "unknown"  # "valid", "invalid", "not_found", "pending"
    message: str = ""


class VerifyHashRequest(BaseRequest):
    """Request to verify a document hash."""
    file_hash: str = Field(..., description="SHA-256 hash of the PDF file")


class VerifyHashResponse(BaseModel):
    """Response from hash verification."""
    matches: bool
    verification_id: str
    expected_hash: str
    provided_hash: str
    message: str = ""


# Error Response
class ErrorResponse(BaseModel):
    error: bool = True
    code: str
    message: str
    details: Optional[dict] = None
    request_id: Optional[str] = None


# Internal Models
class AuthenticatedUser(BaseModel):
    user_id: str  # This is the Google 'sub'
    internal_user_id: Optional[str] = None # This is the Supabase 'auth.users.id' UUID
    workspace_id: str
    email: Optional[str] = None
    name: Optional[str] = None
    picture: Optional[str] = None
    role: Optional[str] = None


class SigningSession(BaseModel):
    id: str
    document_id: str
    signer_id: str
    workspace_id: str
    token_hash: str
    phone: Optional[str] = None
    email: Optional[str] = None
    name: str
    status: SignerStatus
    verification_method: Optional[str] = None  # "none", "sms", "whatsapp" - determines OTP requirement
    otp_verified_at: Optional[datetime] = None
    signed_at: Optional[datetime] = None
    viewed_at: Optional[datetime] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class Document(BaseModel):
    id: str
    workspace_id: str
    name: str
    status: DocumentStatus
    gcs_original_path: Optional[str] = None
    gcs_pdf_path: Optional[str] = None
    gcs_signed_path: Optional[str] = None
    gcs_evidence_path: Optional[str] = None
    page_count: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    created_by: str


class DocumentEvent(BaseModel):
    id: Optional[str] = None
    document_id: str
    workspace_id: str
    user_id: Optional[str] = None
    signer_id: Optional[str] = None
    event_type: EventType
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Optional[dict] = None
    created_at: Optional[datetime] = None

# V2 Models for new frontend contracts
class DocumentInfo(BaseModel):
    title: str

class SignerInfo(BaseModel):
    name: str
    phone: Optional[str] = None
    email: Optional[str] = None

class PlacementDefaults(BaseModel):
    page: int = 1
    x: int = 400
    y: int = 100
    w: int = 150
    h: int = 50

class OTPStatus(str, Enum):
    """OTP verification status."""
    NOT_REQUIRED = "not_required"  # No phone number, OTP not needed
    REQUIRED = "required"          # OTP required but not sent yet
    SENT = "sent"                  # OTP sent, waiting for verification
    VERIFIED = "verified"          # OTP verified successfully
    LOCKED = "locked"              # Too many failed attempts, temporarily locked


class SignerHint(BaseModel):
    """Masked signer info for display."""
    email_masked: Optional[str] = None  # e.g., "j***@example.com"
    phone_masked: Optional[str] = None  # e.g., "+420***789"


class ValidateSessionV2Response(BaseModel):
    document: DocumentInfo
    signer: SignerInfo
    signer_hint: Optional[SignerHint] = None
    otp_required: bool
    otp_status: OTPStatus = OTPStatus.NOT_REQUIRED
    pdf_url: Optional[str] = None
    placement_defaults: PlacementDefaults = Field(default_factory=PlacementDefaults)
    status: SignerStatus
    expired: bool
    expires_in_seconds: Optional[int] = None  # Seconds until session expires
    whatsapp_available: bool = True


# Email Template Models
class EmailTemplateUpdate(BaseRequest):
    """Request to create/update an email template."""
    subject: str = Field(..., min_length=1, max_length=500)
    html: str = Field(..., min_length=1)
    text: Optional[str] = None


class EmailTemplate(BaseModel):
    """Email template response model."""
    id: Optional[str] = None
    workspace_id: Optional[str] = None
    type: EmailTemplateType
    subject: str
    html: str
    text: Optional[str] = None
    is_default: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class EmailTemplateContext(BaseModel):
    """Context for rendering email templates."""
    # Common fields
    document_name: str
    workspace_name: str

    # For DOCUMENT_SEND and REMINDER
    signer_name: Optional[str] = None
    signing_link: Optional[str] = None
    sign_url: Optional[str] = None  # Alias for signing_link (some templates use this)
    expires_at: Optional[str] = None
    message: Optional[str] = None
    sender_name: Optional[str] = None

    # For DOCUMENT_SIGNED
    signed_at: Optional[str] = None

    # For ALL_SIGNED
    completed_at: Optional[str] = None
    download_link: Optional[str] = None


# =============================================================================
# Public Signing API Models (v2 - flat structure for FE)
# =============================================================================

class SignField(BaseModel):
    """Signature placement field."""
    id: str = Field(..., description="Unique field identifier")
    page: int = Field(..., ge=1, description="Page number (1-indexed)")
    x: float = Field(..., ge=0, description="X coordinate in PDF points")
    y: float = Field(..., ge=0, description="Y coordinate in PDF points")
    w: float = Field(..., gt=0, description="Width in PDF points")
    h: float = Field(..., gt=0, description="Height in PDF points")


class SigningSessionResponse(BaseModel):
    """
    GET /v1/signing/sessions/{token} response.
    Flat structure matching FE contract.

    Status values:
    - "valid": Session is valid, ready for signing
    - "completed": Document already signed (includes signed_pdf_url if available)
    """
    status: str = Field(default="valid", description="Session status: valid | completed")
    document_name: str = Field(..., description="Name of the document")
    signer_name: str = Field(..., description="Name of the signer")
    signer_email_masked: Optional[str] = Field(None, description="Masked email")
    signer_phone_masked: Optional[str] = Field(None, description="Masked phone")
    # For status="valid" - signing info
    expires_at: Optional[datetime] = Field(None, description="Session expiry time")
    expires_in_seconds: Optional[int] = Field(None, description="Seconds until expiry")
    requires_otp: Optional[bool] = Field(None, description="OTP verification required")
    otp_status: Optional[OTPStatus] = Field(None, description="Current OTP status")
    pdf_preview_url: Optional[str] = Field(None, description="Signed URL for PDF preview")
    page_count: Optional[int] = Field(None, description="Number of pages")
    sign_fields: List[SignField] = Field(default_factory=list, description="Signature fields")
    whatsapp_available: bool = Field(default=True, description="WhatsApp OTP available")
    document_checksum: Optional[str] = Field(None, description="SHA-256 of document")
    # For status="completed" - signed document info
    signed_pdf_url: Optional[str] = Field(None, description="URL to download signed PDF")
    signed_at: Optional[datetime] = Field(None, description="When document was signed")


class SigningErrorCode(str, Enum):
    """Error codes for signing flow."""
    # Token/session errors
    SIGN_LINK_INVALID = "SIGN_LINK_INVALID"
    SIGN_LINK_EXPIRED = "SIGN_LINK_EXPIRED"
    SIGN_ALREADY_COMPLETED = "SIGN_ALREADY_COMPLETED"
    # OTP errors
    OTP_NOT_VERIFIED = "OTP_NOT_VERIFIED"
    OTP_INVALID = "OTP_INVALID"
    OTP_RATE_LIMITED = "OTP_RATE_LIMITED"  # Alias-compatible with TOO_MANY_REQUESTS
    TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS"  # Legacy, use OTP_RATE_LIMITED
    OTP_TOO_MANY_ATTEMPTS = "OTP_TOO_MANY_ATTEMPTS"
    # Signing errors
    SIGNING_IN_PROGRESS = "SIGNING_IN_PROGRESS"  # Concurrent signing attempt
    VALIDATION_ERROR = "VALIDATION_ERROR"
    SERVER_ERROR = "SERVER_ERROR"


# Alias mapping: canonical code → legacy code (for backward compatibility)
ERROR_CODE_ALIASES = {
    "SIGN_LINK_INVALID": "TOKEN_NOT_FOUND",
    "SIGN_LINK_EXPIRED": "TOKEN_EXPIRED",
    "TOO_MANY_REQUESTS": "OTP_RATE_LIMITED",
    "OTP_RATE_LIMITED": "OTP_RATE_LIMITED",
    "SIGN_ALREADY_COMPLETED": "ALREADY_SIGNED",
    "SIGNING_IN_PROGRESS": "SIGNING_IN_PROGRESS",
}


class SigningErrorResponse(BaseModel):
    """Error response for signing endpoints."""
    error: bool = True
    code: SigningErrorCode
    message: str
    # Alias code for FE compatibility (e.g., TOKEN_NOT_FOUND for SIGN_LINK_INVALID)
    alias_code: Optional[str] = None
    details: Optional[dict] = None
    remaining_attempts: Optional[int] = None
    retry_after_seconds: Optional[int] = None
    locked_until: Optional[datetime] = None
    expired_at: Optional[datetime] = None
    signed_at: Optional[datetime] = None

    def model_post_init(self, __context) -> None:
        """Auto-populate alias_code from ERROR_CODE_ALIASES."""
        if self.alias_code is None and self.code:
            self.alias_code = ERROR_CODE_ALIASES.get(self.code.value)


class OtpSendRequestV2(BaseRequest):
    """POST /v1/signing/sessions/{token}/otp/send request."""
    channel: OTPChannel


class OtpSendResponseV2(BaseModel):
    """POST /v1/signing/sessions/{token}/otp/send response."""
    status: str = "otp_sent"
    channel: OTPChannel
    retry_after_seconds: int = 60


class OtpVerifyRequestV2(BaseRequest):
    """POST /v1/signing/sessions/{token}/otp/verify request."""
    code: str = Field(..., min_length=4, max_length=6, pattern=r"^[0-9]+$")


class OtpVerifyResponseV2(BaseModel):
    """POST /v1/signing/sessions/{token}/otp/verify response."""
    status: str = "verified"


class SignCompleteRequest(BaseRequest):
    """POST /v1/signing/sessions/{token}/complete request."""
    signature_image_base64: str = Field(..., min_length=100)
    field_id: Optional[str] = Field(None, description="Sign field ID")
    consent_accepted: bool = Field(..., description="User consent required")

    @field_validator("signature_image_base64")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        try:
            if v.startswith("data:image/png;base64,"):
                v = v[22:]
            decoded = base64.b64decode(v)
            if not decoded[:8] == b'\x89PNG\r\n\x1a\n':
                raise ValueError("Invalid PNG signature")
            return v
        except Exception as e:
            raise ValueError(f"Invalid base64 PNG image: {e}")

    @field_validator("consent_accepted")
    @classmethod
    def validate_consent(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Consent is required to sign the document")
        return v


class SignCompleteResponse(BaseModel):
    """POST /v1/signing/sessions/{token}/complete response."""
    status: str = "completed"
    signed_pdf_url: Optional[str] = None
    signed_at: datetime
    message: Optional[str] = None


class SignedStatusResponse(BaseModel):
    """
    GET /v1/signing/sessions/{token}/signed response.
    Used for polling after async submit (202) or for refresh download URL.
    """
    status: str = Field(..., description="signed | processing | failed")
    signed_document_url: Optional[str] = Field(None, description="Fresh signed URL for download")
    document_sha256: Optional[str] = Field(None, description="SHA-256 hash of signed document")
    signed_at: Optional[datetime] = Field(None, description="Signing timestamp (UTC)")
    verification_id: Optional[str] = Field(None, description="Public verification ID")
    failure_reason: Optional[str] = Field(None, description="Reason if status=failed")
