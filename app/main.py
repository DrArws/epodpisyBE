"""
E-Signing Service - Main FastAPI Application
Production backend for electronic document signing.
"""
import logging
import os
import shutil
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import FastAPI, Depends, Request, Path, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from app.config import get_settings, Settings
from app.auth import (
    get_current_user,
    get_admin_or_user,
    verify_admin_secret,
    get_signing_session_from_token,
    verify_workspace_access,
    get_client_ip,
    AuthenticationError,
    AuthorizationError,
)
from app.models import (
    AuthenticatedUser,
    SigningSession,
    UploadUrlRequest,
    UploadUrlResponse,
    ConvertToPdfRequest,
    ConvertToPdfResponse,
    SendOTPRequest,
    OTPSendResponse,
    VerifyOTPRequest,
    OTPVerifyResponse,
    SignRequest,
    SignResponse,
    FinalizeResponse,
    EventType,
    SignerStatus,
    DocumentStatus,
    OTPChannel,
    CreateDocumentRequest,
    SendDocumentRequest,
    DocumentResponse,
    DocumentListResponse,
    SignerResponse,
    SendDocumentResponse,
    DownloadLinksResponse,
    ValidateSessionResponse,
    ValidateSessionV2Response,
    DocumentInfo,
    SignerInfo,
    SignerHint,
    OTPStatus,
    VerifyResponse,
    VerifyHashRequest,
    VerifyHashResponse,
    EmailTemplateType,
    EmailTemplateContext,
    AuthorInfo,
    PdfUrlResponse,
)
from app.gcs import get_gcs_client, GCSClient, normalize_storage_path
from app.supabase_client import get_supabase_client, SupabaseClient, get_user_token
from app.otp import get_otp_service, OTPService
from app.pdf import (
    get_pdf_converter,
    get_pdf_signer,
    get_evidence_generator,
    PDFConverter,
    PDFSigner,
    EvidenceReportGenerator,
    StampInfo,
    generate_verification_id,
)
from app.pdf.convert import ConversionError
from app.pdf.sign import SigningError, SignaturePlacement, PlacementValidationError
from app.pdf.evidence import SignerInfo, EventInfo, DocumentInfo
from app.utils.logging import (
    setup_logging,
    RequestIdMiddleware,
    set_context,
    get_logger,
)
# Rate limiting now uses DB columns in signing_sessions table
from app.utils.security import compute_file_hash
from app.utils.datetime_utils import utc_now, parse_db_timestamp, is_expired
from app.utils.rate_limiter import get_verify_rate_limiter
from app.exceptions import (
    AppException,
    NotFoundError,
    ValidationException,
    ConversionException,
    SigningException,
    OTPException,
    RateLimitException,
    app_exception_handler,
    http_exception_handler,
    validation_exception_handler,
    generic_exception_handler,
)

logger = get_logger(__name__)


def validate_uuid(value: str, field_name: str = "ID") -> str:
    """Validate that a string is a valid UUID."""
    try:
        uuid.UUID(value)
        return value
    except (ValueError, AttributeError):
        raise ValidationException(f"Invalid {field_name}: '{value}' is not a valid UUID")


def parse_document_status(status: str) -> DocumentStatus:
    """Parse document status with fallback for unknown values."""
    try:
        return DocumentStatus(status)
    except ValueError:
        logger.warning(f"Unknown document status: {status}, defaulting to DRAFT")
        return DocumentStatus.DRAFT


def parse_signer_status(status: str) -> SignerStatus:
    """Parse signer status with fallback for unknown values."""
    try:
        return SignerStatus(status)
    except ValueError:
        logger.warning(f"Unknown signer status: {status}, defaulting to PENDING")
        return SignerStatus.PENDING


def mask_email(email: Optional[str]) -> Optional[str]:
    """Mask email for display: john@example.com -> j***@example.com"""
    if not email or "@" not in email:
        return None
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        return f"*@{domain}"
    return f"{local[0]}***@{domain}"


def mask_phone(phone: Optional[str]) -> Optional[str]:
    """Mask phone for display: +420123456789 -> ***6789 (last 4 digits)"""
    if not phone:
        return None
    # Show only last 4 digits as per FE spec
    if len(phone) >= 4:
        return "***" + phone[-4:]
    return "***"


def compute_otp_status(
    has_phone: bool,
    otp_channel: Optional[str],
    otp_verified_at: Optional[str],
) -> OTPStatus:
    """Determine OTP status based on session state."""
    if not has_phone:
        return OTPStatus.NOT_REQUIRED
    if otp_verified_at:
        return OTPStatus.VERIFIED
    if otp_channel:
        return OTPStatus.SENT
    return OTPStatus.REQUIRED


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    settings = get_settings()
    setup_logging(
        environment=settings.environment,
        level=logging.DEBUG if settings.debug else logging.INFO,
    )
    logger.info(f"Starting E-Signing Service v1.0.0 ({settings.environment})")
    yield
    logger.info("Shutting down E-Signing Service")


app = FastAPI(
    title="E-Signing Service",
    description="""Backend service for electronic document signing.

## Authentication

This API supports two authentication methods:

### 1. Google ID Token (Frontend calls)
Use `Authorization: Bearer <google_id_token>` header with a valid Google ID token.

### 2. Admin Secret + User ID (Edge Function calls)
For server-to-server communication from Supabase Edge Functions, use:
- `X-Admin-Secret`: Admin API secret for authentication
- `X-User-ID`: User's Supabase UUID (required when using admin secret)
- `X-User-Email`: User's email (optional)
- `X-User-Name`: User's display name (optional)
- `X-Workspace-ID`: Workspace UUID (required for all authenticated endpoints)
""",
    version="1.0.0",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "users", "description": "User profile operations"},
        {"name": "documents", "description": "Document management operations"},
        {"name": "signing", "description": "Document signing operations (public, token-based)"},
        {"name": "health", "description": "Health check endpoints"},
        {"name": "analysis", "description": "Log analysis endpoints"},
    ],
)


from app.routers import health, auth_router, analysis, signing, internal

# Middleware
app.add_middleware(RequestIdMiddleware)

# Production-safe CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://podpisy.lovable.app",
        "https://lovable.dev",
        "http://localhost:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handlers
app.add_exception_handler(AppException, app_exception_handler)
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(ValidationError, validation_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# Routers
app.include_router(health.router)
app.include_router(auth_router.router)
app.include_router(analysis.router, prefix="/v1/analysis", tags=["analysis"])
app.include_router(signing.router)  # Public signing API v2
app.include_router(internal.router) # Internal service-to-service API


# Custom OpenAPI schema with security schemes
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    from fastapi.openapi.utils import get_openapi

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "Google ID Token for frontend authentication",
        },
        "AdminSecret": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Admin-Secret",
            "description": "Admin API secret for Edge Function authentication",
        },
        "UserID": {
            "type": "apiKey",
            "in": "header",
            "name": "X-User-ID",
            "description": "User's Supabase UUID (required with X-Admin-Secret)",
        },
        "WorkspaceID": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Workspace-ID",
            "description": "Workspace UUID for multi-tenant access",
        },
    }

    # Add global security (optional - shows in UI)
    openapi_schema["security"] = [
        {"BearerAuth": [], "WorkspaceID": []},
        {"AdminSecret": [], "UserID": [], "WorkspaceID": []},
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint for Cloud Run."""
    return {"status": "healthy", "version": "1.0.0"}


# ============================================================================
# User Endpoints
# ============================================================================

@app.get(
    "/v1/me",
    response_model=AuthenticatedUser,
    tags=["users"],
    summary="Get Current User",
    description="Returns the profile of the currently authenticated user based on the provided Google ID token.",
)
async def get_me(user: AuthenticatedUser = Depends(get_current_user)):
    """
    Provides a simple way for the frontend to get the current user's
    details, including name, email, and picture.
    """
    return user


# ============================================================================
# Document Endpoints (authenticated via JWT)
# ============================================================================

@app.get(
    "/v1/documents",
    response_model=DocumentListResponse,
)
async def list_documents(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(default=None, description="Filter by status"),
    user: AuthenticatedUser = Depends(get_current_user),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    List documents for the authenticated user's workspace.
    Supports pagination and status filtering.
    """
    logger.info(f"Listing documents for workspace {user.workspace_id}")

    # Build query
    query = supabase.table("documents").select(
        "*, document_signers(*)", count="exact"
    ).eq("workspace_id", user.workspace_id)

    if status:
        query = query.eq("status", status)
    else:
        # Default to active statuses if none provided
        query = query.in_("status", [
            DocumentStatus.SENT.value,
            DocumentStatus.PENDING.value,
            DocumentStatus.IN_PROGRESS.value
        ])

    # Apply pagination
    offset = (page - 1) * page_size
    query = query.order("created_at", desc=True).range(offset, offset + page_size - 1)

    result = query.execute()

    # Batch lookup authors (avoid N+1 queries)
    author_ids = [doc["created_by"] for doc in (result.data or []) if doc.get("created_by")]
    authors_map = await supabase.get_users_by_ids(author_ids)

    # Transform to response
    documents = []
    for doc in result.data or []:
        signers = []
        for s in doc.get("document_signers", []) or []:
            signers.append(SignerResponse(
                id=s["id"],
                name=s.get("name", "Unknown"),
                email=s.get("email"),
                phone=s.get("phone"),
                status=parse_signer_status(s.get("status", "pending")),
                signing_order=s.get("signing_order", 1),
                verification=s.get("verification"),
                viewed_at=s.get("viewed_at"),
                signed_at=s.get("signed_at"),
            ))

        # Build author info
        author = None
        created_by = doc.get("created_by")
        if created_by:
            user_data = authors_map.get(created_by)
            author = AuthorInfo(
                id=created_by,
                name=user_data.get("name", "Neznámý") if user_data else "Neznámý",
                email=user_data.get("email", "") if user_data else "",
            )

        documents.append(DocumentResponse(
            id=doc["id"],
            name=doc["name"],
            status=parse_document_status(doc["status"]),
            workspace_id=doc["workspace_id"],
            gcs_pdf_path=doc.get("gcs_pdf_path"),
            page_count=doc.get("page_count"),
            created_at=doc["created_at"],
            completed_at=doc.get("completed_at"),
            created_by=doc["created_by"],
            author=author,
            signers=signers,
        ))

    return DocumentListResponse(
        documents=documents,
        total=result.count or 0,
        page=page,
        page_size=page_size,
    )


@app.post(
    "/v1/documents",
    response_model=DocumentResponse,
    status_code=201,
)
async def create_document(
    request: Request,
    request_body: CreateDocumentRequest,
    user: AuthenticatedUser = Depends(get_admin_or_user),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Create a new document with signers.
    Accepts user JWT, or admin secret + user JWT (for Edge Functions).
    """
    workspace_id = user.workspace_id
    if not user.internal_user_id:
        raise HTTPException(status_code=404, detail="Internal user ID not found.")

    logger.info(f"Creating document: {request_body.name} by user {user.internal_user_id}")

    # Create document
    doc_data = {
        "name": request_body.name,
        "workspace_id": workspace_id,
        "status": DocumentStatus.DRAFT.value,
        "created_by": user.internal_user_id,
        "created_at": utc_now().isoformat(),
    }

    # Use admin_insert when no user token (admin secret auth), otherwise use direct insert
    use_admin_proxy = get_user_token() is None

    if use_admin_proxy:
        document = await supabase.admin_insert("documents", doc_data)
    else:
        doc_result = supabase.table("documents").insert(doc_data).execute()
        document = doc_result.data[0]
    document_id = document["id"]

    set_context(document_id=document_id)

    # Create signers
    signers = []
    for signer_input in request_body.signers:
        # Map verification field - only include if explicitly provided
        verification_provided = signer_input.verification is not None
        verification_value = signer_input.verification.value if verification_provided else None

        signer_data = {
            "document_id": document_id,
            "workspace_id": workspace_id,
            "name": signer_input.name,
            "email": signer_input.email,
            "phone": signer_input.phone,
            "signing_order": signer_input.signing_order,
            "status": SignerStatus.PENDING.value,
            "created_at": utc_now().isoformat(),
        }

        # Only set verification if explicitly provided (preserve DB default otherwise)
        if verification_provided:
            signer_data["verification"] = verification_value

        if use_admin_proxy:
            signer = await supabase.admin_insert("document_signers", signer_data)
        else:
            signer_result = supabase.table("document_signers").insert(signer_data).execute()
            signer = signer_result.data[0]

        # Log signer creation with verification info (no PII)
        logger.info(
            f"Signer created: document_id={document_id}, "
            f"signer_id={signer['id']}, "
            f"verification_final={signer.get('verification', 'db_default')}, "
            f"verification_provided={verification_provided}"
        )

        signers.append(SignerResponse(
            id=signer["id"],
            name=signer["name"],
            email=signer.get("email"),
            phone=signer.get("phone"),
            status=SignerStatus.PENDING,
            signing_order=signer["signing_order"],
            verification=signer.get("verification"),
        ))

    # Create event
    await supabase.create_event(
        document_id=document_id,
        workspace_id=workspace_id,
        user_id=user.internal_user_id,
        event_type=EventType.DOCUMENT_CREATED,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("User-Agent"),
        metadata={"name": request_body.name, "signers_count": len(signers)},
    )

    logger.info(f"Document created: {document_id} with {len(signers)} signers")

    return DocumentResponse(
        id=document_id,
        name=document["name"],
        status=DocumentStatus.DRAFT,
        workspace_id=document["workspace_id"],
        created_at=document["created_at"],
        created_by=document["created_by"],
        signers=signers,
    )


@app.get(
    "/v1/documents/{document_id}",
    response_model=DocumentResponse,
)
async def get_document(
    request: Request,
    document_id: str = Path(..., description="Document ID"),
    user: AuthenticatedUser = Depends(get_admin_or_user),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Get document details by ID.
    Accepts user JWT, or admin secret + user JWT (for Edge Functions).
    """
    # Validate UUID format
    validate_uuid(document_id, "document_id")

    set_context(document_id=document_id)
    logger.info(f"Getting document {document_id}")

    workspace_id = user.workspace_id

    # Get document (using admin proxy to bypass RLS)
    document = await supabase.get_document(document_id, workspace_id)
    if not document:
        raise NotFoundError("Document", document_id)

    # Get signers (using admin proxy to bypass RLS)
    signers_data = await supabase.get_signers(document_id, workspace_id)

    # Transform signers
    signers = []
    for s in signers_data or []:
        signers.append(SignerResponse(
            id=s["id"],
            name=s.get("name", "Unknown"),
            email=s.get("email"),
            phone=s.get("phone"),
            status=parse_signer_status(s.get("status", "pending")),
            signing_order=s.get("signing_order", 1),
            verification=s.get("verification"),
            viewed_at=s.get("viewed_at"),
            signed_at=s.get("signed_at"),
        ))

    # Lookup author info
    author = None
    if document.created_by:
        user_data = await supabase.get_user_by_id(document.created_by)
        author = AuthorInfo(
            id=document.created_by,
            name=user_data.get("name", "Neznámý") if user_data else "Neznámý",
            email=user_data.get("email", "") if user_data else "",
        )

    return DocumentResponse(
        id=document.id,
        name=document.name,
        status=parse_document_status(document.status),
        workspace_id=document.workspace_id,
        gcs_pdf_path=document.gcs_pdf_path,
        page_count=document.page_count,
        created_at=document.created_at,
        completed_at=document.completed_at,
        created_by=document.created_by,
        author=author,
        signers=signers,
    )


@app.get(
    "/v1/documents/{document_id}/pdf-url",
    response_model=PdfUrlResponse,
    tags=["documents"],
    summary="Get PDF Preview URL",
    description="Generate a short-lived GCS signed URL for PDF preview. Returns URL valid for 10 minutes.",
)
async def get_document_pdf_url(
    request: Request,
    document_id: str = Path(..., description="Document ID"),
    user: AuthenticatedUser = Depends(get_admin_or_user),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Get a signed GCS URL for PDF preview.
    Uses gcs_pdf_path (original PDF) with fallback to gcs_signed_path if available.
    URL expires in 10 minutes (600 seconds).
    """
    # Validate UUID format
    validate_uuid(document_id, "document_id")

    set_context(document_id=document_id)
    logger.info(f"Getting PDF URL for document {document_id}")

    workspace_id = user.workspace_id

    # Get document (using admin proxy to bypass RLS)
    document = await supabase.get_document(document_id, workspace_id)
    if not document:
        raise NotFoundError("Document", document_id)

    # Prefer gcs_pdf_path, fallback to gcs_signed_path
    pdf_path = document.gcs_pdf_path or document.gcs_signed_path
    if not pdf_path:
        raise ValidationException("Document has no PDF available for preview")

    # Check if file exists in GCS
    if not gcs.blob_exists(pdf_path):
        raise NotFoundError("PDF file", pdf_path)

    # Generate signed URL with 10 minute expiration
    expiration_minutes = 10
    try:
        pdf_url = gcs.generate_download_signed_url(
            pdf_path,
            expiration_minutes=expiration_minutes,
            filename=f"{document.name}.pdf",
        )
    except FileNotFoundError:
        raise NotFoundError("PDF file", pdf_path)

    logger.info(f"Generated PDF preview URL for document {document_id}")

    return PdfUrlResponse(
        pdf_url=pdf_url,
        expires_in=expiration_minutes * 60,  # 600 seconds
    )


@app.get(
    "/v1/documents/{document_id}/signed-pdf-url",
    response_model=PdfUrlResponse,
    tags=["documents"],
    summary="Get Signed PDF Download URL",
    description="Generate a short-lived GCS signed URL for downloading the signed PDF.",
)
async def get_signed_pdf_url(
    request: Request,
    document_id: str = Path(..., description="Document ID"),
    user: AuthenticatedUser = Depends(get_admin_or_user),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Get a signed GCS URL for downloading the signed PDF.
    Returns 404 if document has no signed PDF yet.
    URL expires in 10 minutes (600 seconds).
    """
    validate_uuid(document_id, "document_id")

    set_context(document_id=document_id)
    logger.info(f"Getting signed PDF URL for document {document_id}")

    workspace_id = user.workspace_id

    document = await supabase.get_document(document_id, workspace_id)
    if not document:
        raise NotFoundError("Document", document_id)

    if not document.gcs_signed_path:
        raise ValidationException("Document has not been signed yet")

    if not gcs.blob_exists(document.gcs_signed_path):
        raise NotFoundError("Signed PDF file", document.gcs_signed_path)

    expiration_minutes = 10
    try:
        pdf_url = gcs.generate_download_signed_url(
            document.gcs_signed_path,
            expiration_minutes=expiration_minutes,
            filename=f"{document.name}_signed.pdf",
        )
    except FileNotFoundError:
        raise NotFoundError("Signed PDF file", document.gcs_signed_path)

    logger.info(f"Generated signed PDF URL for document {document_id}")

    return PdfUrlResponse(
        pdf_url=pdf_url,
        expires_in=expiration_minutes * 60,
    )


@app.post(
    "/v1/documents/{document_id}/upload-url",
    response_model=UploadUrlResponse,
)
async def create_upload_url(
    document_id: str = Path(..., description="Document ID"),
    request_body: UploadUrlRequest = ...,
    user: AuthenticatedUser = Depends(get_current_user),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Generate a signed URL for direct file upload to GCS.
    Frontend will PUT the file directly to this URL.
    """
    # Validate UUID format
    validate_uuid(document_id, "document_id")

    set_context(document_id=document_id)
    logger.info(f"Creating upload URL for {request_body.filename}")

    # Verify document exists and user has access
    document = await supabase.get_document(document_id, user.workspace_id)
    if not document:
        raise NotFoundError("Document", document_id)

    # Generate signed upload URL
    signed_url, gcs_path, expiration_seconds = gcs.generate_upload_signed_url(
        workspace_id=user.workspace_id,
        document_id=document_id,
        filename=request_body.filename,
        content_type=request_body.content_type,
        folder="uploads",
    )

    logger.info(f"Generated upload URL for {gcs_path}")

    return UploadUrlResponse(
        signed_upload_url=signed_url,
        gcs_path=gcs_path,
        expires_in_seconds=expiration_seconds,
    )


@app.post(
    "/v1/documents/{document_id}/convert-to-pdf",
    response_model=ConvertToPdfResponse,
)
async def convert_to_pdf(
    document_id: str = Path(..., description="Document ID"),
    request_body: ConvertToPdfRequest = ...,
    user: AuthenticatedUser = Depends(get_current_user),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
    converter: PDFConverter = Depends(get_pdf_converter),
    settings: Settings = Depends(get_settings),
):
    """
    Convert uploaded file to PDF.
    Downloads from GCS, converts, uploads PDF back to GCS.
    """
    # Validate UUID format
    validate_uuid(document_id, "document_id")

    set_context(document_id=document_id)
    logger.info(f"Converting {request_body.filename} to PDF")

    # Normalize storage path (handles legacy FE formats)
    normalized_path = normalize_storage_path(request_body.storage_path)

    # Verify document exists and user has access
    document = await supabase.get_document(document_id, user.workspace_id)
    if not document:
        raise NotFoundError("Document", document_id)

    # Create temp directory for this conversion
    temp_dir = tempfile.mkdtemp(prefix="convert_")
    local_input = os.path.join(temp_dir, f"input_{uuid.uuid4()}")
    local_pdf = None

    try:
        # Download file from GCS (using normalized path)
        gcs.download_to_file(normalized_path, local_input)

        # Convert to PDF
        try:
            local_pdf, page_count = converter.convert_to_pdf(
                input_path=local_input,
                content_type=request_body.content_type,
                original_filename=request_body.filename,
            )
        except ConversionError as e:
            raise ConversionException(str(e))

        # Upload PDF to GCS
        pdf_gcs_path = f"{user.workspace_id}/{document_id}/pdf/{uuid.uuid4()}.pdf"
        gcs.upload_from_file(local_pdf, pdf_gcs_path, "application/pdf")

        # Generate download URL
        pdf_download_url = gcs.generate_download_signed_url(
            pdf_gcs_path,
            filename=f"{os.path.splitext(request_body.filename)[0]}.pdf",
        )

        # Update document in Supabase
        await supabase.update_document(
            document_id=document_id,
            workspace_id=user.workspace_id,
            updates={
                "gcs_original_path": request_body.storage_path,
                "gcs_pdf_path": pdf_gcs_path,
                "page_count": page_count,
            },
        )

        # Create event
        await supabase.create_event(
            document_id=document_id,
            workspace_id=user.workspace_id,
            user_id=user.internal_user_id,
            event_type=EventType.DOCUMENT_CONVERTED_TO_PDF,
            metadata={
                "original_filename": request_body.filename,
                "content_type": request_body.content_type,
                "page_count": page_count,
            },
        )

        logger.info(f"Converted to PDF: {pdf_gcs_path} ({page_count} pages)")

        return ConvertToPdfResponse(
            pdf_gcs_path=pdf_gcs_path,
            pdf_download_url=pdf_download_url,
            page_count=page_count,
        )

    finally:
        # Cleanup temp files
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")


@app.post(
    "/v1/documents/{document_id}/send",
    response_model=SendDocumentResponse,
)
async def send_document(
    request: Request,
    document_id: str = Path(..., description="Document ID"),
    request_body: SendDocumentRequest = ...,
    user: AuthenticatedUser = Depends(get_admin_or_user),
    supabase: SupabaseClient = Depends(get_supabase_client),
    settings: Settings = Depends(get_settings),
):
    """
    Send document for signing - creates signing sessions and sends links.
    Accepts user JWT, or admin secret + user JWT (for Edge Functions).
    """
    # Validate UUID format
    validate_uuid(document_id, "document_id")

    set_context(document_id=document_id)
    logger.info(f"Sending document {document_id} for signing")

    workspace_id = user.workspace_id

    # Verify document exists and has PDF
    document = await supabase.get_document(document_id, workspace_id)
    if not document:
        raise NotFoundError("Document", document_id)

    if not document.gcs_pdf_path:
        raise ValidationException("Document must have a PDF before sending")

    # Get signers
    signers = await supabase.get_signers(document_id, workspace_id)
    if not signers:
        raise ValidationException("Document must have at least one signer")

    # Get workspace name for email templates (fallback to "Podpisy" if not available)
    try:
        workspace_result = supabase.table("workspaces").select("name").eq("id", workspace_id).single().execute()
        workspace_name = workspace_result.data.get("name", "Podpisy") if workspace_result.data else "Podpisy"
    except Exception:
        workspace_name = "Podpisy"

    from app.utils.security import generate_signing_token
    from app.models import SignerWithLink, DeliveryAttempt, DeliveryStatus, DeliverySummary
    from app.email import get_email_service

    email_service = get_email_service()

    # Delivery tracking
    emails_sent = 0
    emails_failed = 0
    sms_sent = 0
    sms_failed = 0

    # Log signing URL configuration for debugging
    sign_app_url = settings.get_sign_app_url()
    logger.info(f"Using SIGN_APP_URL: {sign_app_url} (env: {settings.environment})")

    # Idempotence: Invalidate any existing active sessions for this document
    # This prevents multiple valid links floating around
    existing_sessions = await supabase.admin_select(
        "signing_sessions",
        {"document_id": document_id},
        single=False,
    )

    # Filter active sessions (expires_at > now)
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()
    active_sessions = [s for s in (existing_sessions or []) if s.get("expires_at", "") > now_iso]

    if active_sessions:
        session_ids = [s["id"] for s in active_sessions]
        logger.info(f"Invalidating {len(session_ids)} existing sessions for document {document_id}")
        for sid in session_ids:
            await supabase.admin_update("signing_sessions", sid, {
                "expires_at": now_utc.isoformat(),
                "invalidated_at": now_utc.isoformat(),
            })

        # TODO: Add LINK_REVOKED to DB events_type_chk constraint
        logger.info(f"Revoked {len(session_ids)} previous signing links")

    # Create signing sessions for each signer and collect links
    signers_with_links: List[SignerWithLink] = []

    for signer in signers:
        # Skip signers who already signed
        if signer.get("status") == SignerStatus.SIGNED.value:
            logger.info(f"Skipping signer {signer['id']} - already signed")
            continue

        # Generate secure token
        plain_token, token_hash = generate_signing_token()

        # Create signing session with timezone-aware UTC timestamps
        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        session_data = {
            "document_id": document_id,
            "signer_id": signer["id"],
            "workspace_id": workspace_id,
            "token_hash": token_hash,
            "expires_at": expires_at.isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"Creating signing session for signer_id={signer['id']}, hash_fp={token_hash[:8]}")
        insert_result = await supabase.admin_insert("signing_sessions", session_data)
        logger.info(f"Signing session created: {insert_result.get('id', 'NO ID RETURNED')}")

        # Build signing URL using SIGN_APP_URL (frontend app URL)
        # IMPORTANT: This URL is generated by backend, never by frontend
        sign_url = f"{sign_app_url}/sign/{plain_token}"

        # Initialize delivery tracking for this signer
        email_delivery: Optional[DeliveryAttempt] = None
        sms_delivery: Optional[DeliveryAttempt] = None
        signer_email = signer.get("email")
        signer_phone = signer.get("phone")

        # Send email if requested and not dry_run
        if request_body.send_email:
            if not signer_email:
                email_delivery = DeliveryAttempt(
                    enabled=True,
                    status=DeliveryStatus.SKIPPED,
                    error="No email address provided"
                )
            elif request_body.dry_run:
                email_delivery = DeliveryAttempt(
                    enabled=True,
                    status=DeliveryStatus.NOT_SENT,
                )
            else:
                # Build template context for Edge Function rendering
                # Include both signing_link and sign_url for template compatibility
                context = EmailTemplateContext(
                    document_name=document.name,
                    workspace_name=workspace_name,
                    signer_name=signer["name"],
                    signing_link=sign_url,  # Some templates use {{signing_link}}
                    sign_url=sign_url,       # Some templates use {{sign_url}}
                    expires_at=expires_at.strftime("%d.%m.%Y"),
                    message=request_body.message,
                    sender_name=user.name,
                )
                email_result = await email_service.send_signing_invitation(
                    to_email=signer_email,
                    context=context,
                    workspace_id=workspace_id,
                    http_client=supabase._http_client,
                )
                # Fingerprint for safe logging
                from app.utils.logging import fingerprint
                email_fp = fingerprint(signer_email)

                if email_result.success:
                    logger.info(f"email_send: status=sent, email_fp={email_fp}, message_id={email_result.message_id}")
                    email_delivery = DeliveryAttempt(
                        enabled=True,
                        status=DeliveryStatus.SENT,
                        provider_message_id=email_result.message_id,
                    )
                    emails_sent += 1
                else:
                    logger.warning(f"email_send: status=failed, email_fp={email_fp}, error={email_result.error}")
                    email_delivery = DeliveryAttempt(
                        enabled=True,
                        status=DeliveryStatus.FAILED,
                        error=email_result.error,
                    )
                    emails_failed += 1

        # SMS delivery tracking (placeholder - implement when needed)
        if request_body.send_sms:
            if not signer_phone:
                sms_delivery = DeliveryAttempt(
                    enabled=True,
                    status=DeliveryStatus.SKIPPED,
                    error="No phone number provided"
                )
            elif request_body.dry_run:
                sms_delivery = DeliveryAttempt(
                    enabled=True,
                    status=DeliveryStatus.NOT_SENT,
                )
            else:
                # TODO: Implement SMS sending via Twilio
                sms_delivery = DeliveryAttempt(
                    enabled=True,
                    status=DeliveryStatus.NOT_SENT,
                    error="SMS sending not yet implemented"
                )

        # Add to response list (include both sign_url and signing_link for compatibility)
        signers_with_links.append(SignerWithLink(
            id=signer["id"],
            name=signer["name"],
            email=signer_email,
            phone=signer_phone,
            sign_url=sign_url,
            signing_link=sign_url,  # Frontend expects this field
            expires_at=expires_at,
            email_delivery=email_delivery,
            sms_delivery=sms_delivery,
        ))

        logger.info(f"Created signing session for signer {signer['id']}")

    # Update document status (skip if dry_run)
    if not request_body.dry_run:
        await supabase.update_document(
            document_id=document_id,
            workspace_id=workspace_id,
            updates={
                "status": DocumentStatus.SENT.value,
            },
        )

    # Build delivery summary
    delivery_summary = DeliverySummary(
        send_email=request_body.send_email,
        send_sms=request_body.send_sms,
        dry_run=request_body.dry_run,
        emails_sent=emails_sent,
        emails_failed=emails_failed,
        sms_sent=sms_sent,
        sms_failed=sms_failed,
    )

    # TODO: Add SIGNING_LINK_SENT to DB events_type_chk constraint
    logger.info(
        f"Document {'prepared' if request_body.dry_run else 'sent'}: "
        f"{len(signers_with_links)} signing links created, "
        f"{emails_sent} emails sent, {emails_failed} failed"
    )

    return SendDocumentResponse(
        success=True,
        message="Document prepared for signing (dry run)" if request_body.dry_run else "Document sent for signing",
        signers=signers_with_links,
        document_id=document_id,
        document_name=document.name,
        delivery=delivery_summary,
    )


# ============================================================================
# Email Endpoints
# ============================================================================

@app.post(
    "/v1/test-email",
    tags=["email"],
)
async def send_test_email(
    request: Request,
    template_type: EmailTemplateType = Query(..., description="Template type to test"),
    to_email: str = Query(..., description="Email address to send test to"),
    user: AuthenticatedUser = Depends(get_current_user),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Send a test email using the specified template type.
    Uses mock data to demonstrate the template.
    """
    from app.email import get_email_service

    email_service = get_email_service()

    # Get workspace name
    try:
        workspace_result = supabase.table("workspaces").select("name").eq("id", user.workspace_id).single().execute()
        workspace_name = workspace_result.data.get("name", "Podpisy") if workspace_result.data else "Podpisy"
    except Exception:
        workspace_name = "Podpisy"

    # Build mock context based on template type
    base_context = {
        "document_name": "Testovací dokument.pdf",
        "workspace_name": workspace_name,
    }

    test_sign_url = "https://podpisy.lovable.app/sign/test-token-123"

    if template_type == EmailTemplateType.DOCUMENT_SEND:
        context = EmailTemplateContext(
            **base_context,
            signer_name="Jan Novák (TEST)",
            signing_link=test_sign_url,
            sign_url=test_sign_url,  # Alias for template compatibility
            expires_at="20. ledna 2026",
            message="<p>Toto je testovací email pro ověření šablony.</p>",
            sender_name=user.name or "Odesílatel",
        )
    elif template_type == EmailTemplateType.REMINDER:
        context = EmailTemplateContext(
            **base_context,
            signer_name="Jan Novák (TEST)",
            signing_link=test_sign_url,
            sign_url=test_sign_url,  # Alias for template compatibility
            expires_at="20. ledna 2026",
            message="<p>Připomínka k podpisu testovacího dokumentu.</p>",
        )
    elif template_type == EmailTemplateType.DOCUMENT_SIGNED:
        context = EmailTemplateContext(
            **base_context,
            signer_name="Jan Novák (TEST)",
            signed_at="15. ledna 2026, 14:32",
        )
    elif template_type == EmailTemplateType.ALL_SIGNED:
        context = EmailTemplateContext(
            **base_context,
            completed_at="18. ledna 2026, 16:45",
            download_link="https://podpisy.lovable.app/download/test-doc-123",
        )
    else:
        raise ValidationException(f"Unknown template type: {template_type}")

    # Send test email
    result = await email_service.send_test_email(
        to_email=to_email,
        template_type=template_type,
        context=context,
        workspace_id=user.workspace_id,
        http_client=supabase._http_client,
    )

    from app.utils.logging import fingerprint
    email_fp = fingerprint(to_email)

    if result.success:
        logger.info(f"test_email: status=sent, template={template_type}, email_fp={email_fp}")
        return {
            "success": True,
            "message": f"Test email sent to {to_email}",
            "message_id": result.message_id,
            "template_type": template_type.value,
        }
    else:
        logger.warning(f"test_email: status=failed, template={template_type}, email_fp={email_fp}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {result.error}")


@app.get(
    "/v1/documents/{document_id}/download-links",
    response_model=DownloadLinksResponse,
)
async def get_download_links(
    document_id: str = Path(..., description="Document ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
    settings: Settings = Depends(get_settings),
):
    """
    Get download URLs for all document versions (original, PDF, signed, evidence).
    """
    # Validate UUID format
    validate_uuid(document_id, "document_id")

    set_context(document_id=document_id)
    logger.info(f"Getting download links for document {document_id}")

    # Verify document exists
    document = await supabase.get_document(document_id, user.workspace_id)
    if not document:
        raise NotFoundError("Document", document_id)

    expiration_minutes = settings.gcs_signed_url_expiration_minutes
    expiration_seconds = expiration_minutes * 60

    # Generate URLs for existing files
    original_url = None
    pdf_url = None
    signed_url = None
    evidence_url = None

    if document.gcs_original_path and gcs.blob_exists(document.gcs_original_path):
        original_url = gcs.generate_download_signed_url(
            document.gcs_original_path,
            expiration_minutes=expiration_minutes,
        )

    if document.gcs_pdf_path and gcs.blob_exists(document.gcs_pdf_path):
        pdf_url = gcs.generate_download_signed_url(
            document.gcs_pdf_path,
            expiration_minutes=expiration_minutes,
            filename=f"{document.name}.pdf",
        )

    if document.gcs_signed_path and gcs.blob_exists(document.gcs_signed_path):
        signed_url = gcs.generate_download_signed_url(
            document.gcs_signed_path,
            expiration_minutes=expiration_minutes,
            filename=f"{document.name}_signed.pdf",
        )

    if document.gcs_evidence_path and gcs.blob_exists(document.gcs_evidence_path):
        evidence_url = gcs.generate_download_signed_url(
            document.gcs_evidence_path,
            expiration_minutes=expiration_minutes,
            filename=f"{document.name}_evidence.pdf",
        )

    return DownloadLinksResponse(
        original_url=original_url,
        pdf_url=pdf_url,
        signed_url=signed_url,
        evidence_url=evidence_url,
        expires_in_seconds=expiration_seconds,
    )


@app.post(
    "/v1/documents/{document_id}/finalize",
    response_model=FinalizeResponse,
)
async def finalize_document(
    request: Request,
    document_id: str = Path(..., description="Document ID"),
    user: AuthenticatedUser = Depends(get_current_user),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
    evidence_gen: EvidenceReportGenerator = Depends(get_evidence_generator),
):
    """
    Finalize document: generate evidence report and mark as completed.
    Called after all signers have signed.
    """
    # Validate UUID format
    validate_uuid(document_id, "document_id")

    set_context(document_id=document_id)
    logger.info("Finalizing document")

    # Get document
    document = await supabase.get_document(document_id, user.workspace_id)
    if not document:
        raise NotFoundError("Document", document_id)

    # Check all signers have signed
    pending_count = await supabase.get_pending_signers_count(document_id)
    if pending_count > 0:
        raise ValidationException(
            f"Cannot finalize: {pending_count} signers have not signed yet"
        )

    temp_dir = tempfile.mkdtemp(prefix="finalize_")
    local_pdf = os.path.join(temp_dir, "final.pdf")
    local_evidence = None

    try:
        # Download final signed PDF
        signed_path = document.gcs_signed_path or document.gcs_pdf_path
        gcs.download_to_file(signed_path, local_pdf)

        # Compute hash
        pdf_hash = compute_file_hash(local_pdf)

        # Get page count
        converter = get_pdf_converter()
        page_count = converter.get_pdf_page_count(local_pdf)

        # Get signer details
        signer_details = supabase.get_signer_details_for_evidence(document_id)
        signers = []
        for s in signer_details:
            session = s.get("signing_sessions", {}) or {}
            if isinstance(session, list):
                session = session[0] if session else {}
            signers.append(SignerInfo(
                name=s.get("name", "Unknown"),
                email=s.get("email"),
                phone=s.get("phone"),
                otp_channel=session.get("otp_channel"),
                viewed_at=s.get("viewed_at"),
                otp_verified_at=session.get("otp_verified_at"),
                signed_at=s.get("signed_at"),
                ip_address=session.get("ip_address"),
                user_agent=session.get("user_agent"),
                signature_placement=session.get("signature_placement"),
            ))

        # Get events
        events_data = supabase.get_events(document_id, user.workspace_id)
        events = [
            EventInfo(
                event_type=e.event_type.value if hasattr(e.event_type, 'value') else e.event_type,
                created_at=e.created_at,
                signer_name=None,  # Could be enhanced to include signer name
                ip_address=e.ip_address,
                metadata=e.metadata,
            )
            for e in events_data
        ]

        # Build document info
        doc_info = DocumentInfo(
            id=document.id,
            name=document.name,
            created_at=document.created_at,
            completed_at=utc_now(),
            workspace_id=document.workspace_id,
            final_pdf_hash=pdf_hash,
            page_count=page_count,
        )

        # Generate evidence report
        local_evidence = evidence_gen.generate(doc_info, signers, events)

        # Upload evidence report
        evidence_gcs_path = (
            f"{user.workspace_id}/{document_id}/evidence/"
            f"{uuid.uuid4()}_evidence.pdf"
        )
        gcs.upload_from_file(local_evidence, evidence_gcs_path, "application/pdf")

        # Generate download URL
        evidence_download_url = gcs.generate_download_signed_url(
            evidence_gcs_path,
            filename=f"{document.name}_evidence.pdf",
        )

        # Update document
        completed_at = utc_now()
        await supabase.update_document(
            document_id=document_id,
            workspace_id=user.workspace_id,
            updates={
                "status": DocumentStatus.COMPLETED.value,
                "gcs_evidence_path": evidence_gcs_path,
                "final_hash": pdf_hash,
                "completed_at": completed_at.isoformat(),
            },
        )

        # TODO: Add FINALIZED to DB events_type_chk constraint
        logger.info(f"Document finalized: {document_id}, hash: {pdf_hash}")

        return FinalizeResponse(
            success=True,
            evidence_report_path=evidence_gcs_path,
            evidence_download_url=evidence_download_url,
            document_hash=pdf_hash,
            completed_at=completed_at,
        )

    finally:
        # Cleanup
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")


# ============================================================================
# Signing Session Endpoints (authenticated via magic link token)
# ============================================================================

@app.get(
    "/v1/signing-sessions/{token}/validate",
    response_model=ValidateSessionResponse,
)
async def validate_signing_session(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    settings: Settings = Depends(get_settings),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Validate a signing session token and return session details.
    This is a PUBLIC endpoint - no JWT required.
    """
    try:
        # Validate token and get session
        session = await get_signing_session_from_token(token, request, settings)

        set_context(
            document_id=session.document_id,
            signer_id=session.signer_id,
        )

        # Get document details
        doc_data = supabase.get_document_for_signing(session.document_id)
        if not doc_data:
            raise NotFoundError("Document", session.document_id)

        # Check OTP verification status
        session_data = supabase.get_signing_session(session.token_hash)
        otp_verified = bool(session_data and session_data.get("otp_verified_at"))

        # Generate PDF download URL if available
        pdf_download_url = None
        pdf_path = doc_data.get("gcs_pdf_path")
        if pdf_path and gcs.blob_exists(pdf_path):
            pdf_download_url = gcs.generate_download_signed_url(
                pdf_path,
                expiration_minutes=settings.gcs_signed_url_expiration_minutes,
            )

        # Update signer to viewed status if first view
        if session.status == SignerStatus.PENDING:
            await supabase.update_signer(
                signer_id=session.signer_id,
                workspace_id=session.workspace_id,
                updates={
                    "status": SignerStatus.VIEWED.value,
                    "viewed_at": utc_now().isoformat(),
                },
            )

            # TODO: Add DOCUMENT_VIEWED to DB events_type_chk constraint

        logger.info(f"Session validated for signer {session.signer_id}")

        return ValidateSessionResponse(
            valid=True,
            document_id=session.document_id,
            document_name=doc_data.get("name"),
            signer_name=session.name,
            signer_email=session.email,
            signer_status=SignerStatus(session.status) if session.status else SignerStatus.PENDING,
            requires_otp=bool(session.phone),
            otp_verified=otp_verified,
            pdf_download_url=pdf_download_url,
            page_count=doc_data.get("page_count"),
            message="Session valid",
        )

    except (AuthenticationError, AuthorizationError) as e:
        # Return structured error for invalid/expired sessions
        logger.warning(f"Session validation failed: {e.detail}")
        return ValidateSessionResponse(
            valid=False,
            message=e.detail.get("message", "Invalid session") if isinstance(e.detail, dict) else str(e.detail),
        )


@app.get(
    "/v1/signing-sessions/{token}/validate-v2",
    response_model=ValidateSessionV2Response,
    tags=["signing-sessions"],
)
async def validate_signing_session_v2(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    settings: Settings = Depends(get_settings),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Validate a signing session and return rich, nested data for modern frontends.

    This endpoint NEVER returns 500 - all errors are handled gracefully:
    - Invalid token: returns expired=True, status=DECLINED
    - Database errors: logged, returns error state

    Response includes:
    - signer_hint: masked email/phone for display
    - otp_status: not_required | required | sent | verified
    - expires_in_seconds: time until session expires
    """
    try:
        session = await get_signing_session_from_token(token, request, settings)
        set_context(document_id=session.document_id, signer_id=session.signer_id)

        doc_data = supabase.get_document_for_signing(session.document_id)
        if not doc_data:
            logger.warning(f"Document {session.document_id} not found for signing session")
            return ValidateSessionV2Response(
                document=DocumentInfo(title="Dokument nenalezen"),
                signer=SignerInfo(name=session.name, email=session.email, phone=session.phone),
                otp_required=False,
                otp_status=OTPStatus.NOT_REQUIRED,
                pdf_url=None,
                status=SignerStatus.DECLINED,
                expired=True,
            )

        session_data = supabase.get_signing_session(session.token_hash)

        # Generate short-lived PDF URL (10 min default)
        pdf_download_url = None
        if doc_data.get("gcs_pdf_path") and gcs.blob_exists(doc_data["gcs_pdf_path"]):
            pdf_download_url = gcs.generate_download_signed_url(
                doc_data["gcs_pdf_path"],
                expiration_minutes=settings.gcs_signed_url_expiration_minutes,
            )

        # Safely check expiration and compute expires_in_seconds
        is_expired = False
        expires_in_seconds = None
        if session_data:
            expires_at = session_data.get("expires_at")
            if expires_at:
                try:
                    if isinstance(expires_at, str):
                        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    else:
                        expiry = expires_at
                    now = datetime.now(timezone.utc)
                    is_expired = now > expiry
                    if not is_expired:
                        expires_in_seconds = int((expiry - now).total_seconds())
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not parse expires_at: {expires_at}, error: {e}")

        # Compute OTP status
        otp_status = compute_otp_status(
            has_phone=bool(session.phone),
            otp_channel=session_data.get("otp_channel") if session_data else None,
            otp_verified_at=session_data.get("otp_verified_at") if session_data else None,
        )

        # Create masked hints for display
        signer_hint = SignerHint(
            email_masked=mask_email(session.email),
            phone_masked=mask_phone(session.phone),
        )

        return ValidateSessionV2Response(
            document=DocumentInfo(title=doc_data.get("name", "Dokument")),
            signer=SignerInfo(name=session.name, email=session.email, phone=session.phone),
            signer_hint=signer_hint,
            otp_required=bool(session.phone),
            otp_status=otp_status,
            pdf_url=pdf_download_url,
            status=session.status,
            expired=is_expired,
            expires_in_seconds=expires_in_seconds,
        )

    except (AuthenticationError, AuthorizationError) as e:
        logger.info(f"Session validation failed: {e}")
        return ValidateSessionV2Response(
            document=DocumentInfo(title="Neplatná relace"),
            signer=SignerInfo(name="Neznámý"),
            otp_required=False,
            otp_status=OTPStatus.NOT_REQUIRED,
            pdf_url=None,
            status=SignerStatus.DECLINED,
            expired=True,
        )
    except Exception as e:
        # Catch-all to NEVER return 500
        logger.error(f"Unexpected error in validate_signing_session_v2: {e}", exc_info=True)
        return ValidateSessionV2Response(
            document=DocumentInfo(title="Chyba serveru"),
            signer=SignerInfo(name="Neznámý"),
            otp_required=False,
            otp_status=OTPStatus.NOT_REQUIRED,
            pdf_url=None,
            status=SignerStatus.DECLINED,
            expired=True,
        )


@app.post(
    "/v1/signing-sessions/{token}/otp/send",
    response_model=OTPSendResponse,
)
async def send_otp(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    request_body: SendOTPRequest = ...,
    settings: Settings = Depends(get_settings),
    supabase: SupabaseClient = Depends(get_supabase_client),
    otp_service: OTPService = Depends(get_otp_service),
):
    """
    Send OTP code via SMS or WhatsApp.
    Rate limited via DB columns (max 5/hour).
    """
    # Validate token and get session
    session = await get_signing_session_from_token(token, request, settings)

    set_context(
        document_id=session.document_id,
        signer_id=session.signer_id,
    )

    # DB-based rate limiting
    allowed, error_msg, retry_after = supabase.check_otp_rate_limit(session.id)
    if not allowed:
        raise RateLimitException(retry_after or 3600, error_msg)

    # Check phone number
    if not session.phone:
        raise ValidationException("Phone number is required for OTP verification")

    # Send OTP
    from app.utils.logging import fingerprint, mask_phone
    phone_fp = fingerprint(session.phone)
    logger.info(f"otp_send: channel={request_body.channel.value}, phone_fp={phone_fp}")
    result = await otp_service.send_otp(
        phone=session.phone,
        channel=request_body.channel,
        session_id=session.id,
    )

    if not result.success:
        raise OTPException(result.message)

    # Increment send counter in DB
    supabase.increment_otp_send_count(session.id)

    # Update session with OTP channel
    supabase.update_signing_session(
        session_id=session.id,
        updates={
            "otp_channel": request_body.channel.value,
            "otp_fallback_used": result.fallback_used,
        },
    )

    # TODO: Add OTP_SENT to DB events_type_chk constraint

    return OTPSendResponse(
        success=True,
        channel=request_body.channel,
        message="OTP sent successfully",
    )


@app.post(
    "/v1/signing-sessions/{token}/otp/verify",
    response_model=OTPVerifyResponse,
)
async def verify_otp(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    request_body: VerifyOTPRequest = ...,
    settings: Settings = Depends(get_settings),
    supabase: SupabaseClient = Depends(get_supabase_client),
    otp_service: OTPService = Depends(get_otp_service),
):
    """
    Verify OTP code entered by signer.
    Rate limited via DB (max 5 attempts, then 15min lock).
    """
    # Validate token and get session
    session = await get_signing_session_from_token(token, request, settings)

    set_context(
        document_id=session.document_id,
        signer_id=session.signer_id,
    )

    # DB-based verify attempt limit
    allowed, error_msg = supabase.check_otp_verify_limit(session.id)
    if not allowed:
        raise OTPException(error_msg)

    # Get session data to check OTP settings
    session_data = supabase.get_signing_session(session.token_hash)
    otp_channel = OTPChannel(session_data.get("otp_channel", "sms"))
    fallback_used = session_data.get("otp_fallback_used", False)

    # Verify OTP
    result = await otp_service.verify_otp(
        phone=session.phone,
        code=request_body.code,
        channel=otp_channel,
        session_id=session.id,
        fallback_used=fallback_used,
    )

    if result.success:
        # Reset verify attempts on success
        supabase.reset_otp_verify_attempts(session.id)

        # Update session
        verified_at = utc_now()
        supabase.update_signing_session(
            session_id=session.id,
            updates={
                "otp_verified_at": verified_at.isoformat(),
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("User-Agent", "")[:500],
            },
        )

        # Update signer status
        await supabase.update_signer(
            signer_id=session.signer_id,
            workspace_id=session.workspace_id,
            updates={"status": SignerStatus.VERIFIED.value},
        )

        # TODO: Add OTP_OK to DB events_type_chk constraint
        logger.info(f"otp_verify: status=success, signer_id={session.signer_id}")

        return OTPVerifyResponse(
            success=True,
            verified=True,
            message="OTP verified successfully",
        )
    else:
        # Increment failed attempts (may lock session)
        supabase.increment_otp_verify_attempts(session.id)

        # TODO: Add OTP_FAIL to DB events_type_chk constraint

        return OTPVerifyResponse(
            success=False,
            verified=False,
            message=result.message,
        )


@app.post(
    "/v1/signing-sessions/{token}/sign",
    response_model=SignResponse,
)
async def sign_document(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    request_body: SignRequest = ...,
    settings: Settings = Depends(get_settings),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
    signer: PDFSigner = Depends(get_pdf_signer),
):
    """
    Sign document with signature image.
    Requires OTP verification first.
    """
    import hashlib

    # Get idempotency key from header
    idempotency_key = request.headers.get("Idempotency-Key") or request.headers.get("X-Idempotency-Key")

    # Validate token and get session
    session = await get_signing_session_from_token(token, request, settings)

    set_context(
        document_id=session.document_id,
        signer_id=session.signer_id,
    )

    # Fingerprints for logging (no PII)
    session_fp = hashlib.sha256(str(session.id).encode()).hexdigest()[:8]
    idem_key_fp = hashlib.sha256(idempotency_key.encode()).hexdigest()[:8] if idempotency_key else "none"

    logger.info(f"sign_document: session_fp={session_fp}, idempotency_fp={idem_key_fp}")

    # Check OTP verification
    session_data = supabase.get_signing_session(session.token_hash)
    if not session_data.get("otp_verified_at"):
        raise AuthorizationError(
            "OTP verification required before signing",
            "OTP_NOT_VERIFIED"
        )

    # Check OTP verification is still within TTL (default 10 min)
    otp_verified_at = session_data.get("otp_verified_at")
    if is_expired(otp_verified_at, settings.otp_ttl_seconds):
        logger.info(f"OTP verification expired for session_fp={session_fp}")
        raise AuthorizationError(
            "OTP verification expired. Please verify again.",
            "OTP_EXPIRED"
        )

    # Atomic double-submit protection with signing lock
    acquired, cached_response, reason = supabase.try_acquire_signing_lock(
        session_id=str(session.id),
        idempotency_key=idempotency_key,
    )

    if not acquired:
        logger.info(f"sign_document: lock not acquired, reason={reason}, session_fp={session_fp}")

        if reason == "ALREADY_SIGNED" or reason == "IDEMPOTENT_REPLAY":
            # Return cached response or fetch fresh data
            if cached_response and cached_response.get("signed_pdf_url"):
                return SignResponse(
                    success=True,
                    signed_pdf_url=cached_response["signed_pdf_url"],
                    signed_at=cached_response.get("signed_at"),
                    is_document_complete=cached_response.get("is_document_complete", False),
                    message="Document already signed (idempotent response)",
                )
            # Fallback: fetch current state
            doc_data = supabase.get_document_for_signing(session.document_id)
            if doc_data and doc_data.get("gcs_signed_path"):
                signed_pdf_url = gcs.generate_download_signed_url(
                    doc_data["gcs_signed_path"],
                    expiration_minutes=settings.gcs_signed_url_expiration_minutes,
                    filename=f"{doc_data.get('name', 'document')}_signed.pdf",
                )
                return SignResponse(
                    success=True,
                    signed_pdf_url=signed_pdf_url,
                    signed_at=session_data.get("signed_at"),
                    is_document_complete=supabase.check_all_signed(session.document_id),
                    message="Document already signed (idempotent response)",
                )

        if reason in ("IN_PROGRESS", "RACE_LOST"):
            # Another request is signing
            raise ValidationException("Signing already in progress. Please wait.")

        # SESSION_NOT_FOUND or other
        raise NotFoundError("Session", str(session.id))

    logger.info(f"sign_document: lock acquired, proceeding, session_fp={session_fp}")

    # Get document
    doc_data = supabase.get_document_for_signing(session.document_id)
    if not doc_data:
        raise NotFoundError("Document", session.document_id)

    # Check if document is already completed (all signatures done)
    if doc_data.get("status") == DocumentStatus.COMPLETED.value:
        raise ValidationException(
            "Document is already completed and cannot accept more signatures"
        )

    # Get current PDF path (signed version if exists, otherwise original PDF)
    current_pdf_path = doc_data.get("gcs_signed_path") or doc_data.get("gcs_pdf_path")
    if not current_pdf_path:
        raise ValidationException("Document has no PDF to sign")

    temp_dir = tempfile.mkdtemp(prefix="sign_")
    local_pdf = os.path.join(temp_dir, "current.pdf")
    local_signed = None

    try:
        # Download current PDF
        gcs.download_to_file(current_pdf_path, local_pdf)

        # Generate verification ID (public, human-readable)
        verification_id = generate_verification_id()
        verify_url = f"{settings.app_base_url}/verify/{verification_id}"

        # Create placement object
        placement = SignaturePlacement(
            page=request_body.placement.page,
            x=request_body.placement.x,
            y=request_body.placement.y,
            w=request_body.placement.w,
            h=request_body.placement.h,
        )

        # Prepare verification stamp info
        # NOTE: Hash is NOT included - it will be computed AFTER stamp is added
        otp_channel = session_data.get("otp_channel")
        phone_masked = None
        if session.phone:
            # Mask phone: +420123456789 -> +420***789
            phone = session.phone
            if len(phone) > 6:
                phone_masked = phone[:4] + "***" + phone[-3:]
            else:
                phone_masked = "***"

        signed_at = utc_now()
        stamp_info = StampInfo(
            verification_id=verification_id,
            verify_url=verify_url,
            signer_name=session.name,
            signed_at=signed_at,
            document_id=session.document_id,
            verification_method=otp_channel,
            phone_masked=phone_masked,
            include_qr=True,
        )

        # Sign PDF with PAdES digital signature + visual overlay
        try:
            local_signed, pades_audit = signer.sign_pdf_pades(
                pdf_path=local_pdf,
                signature_png_base64=request_body.signature_png_base64,
                placement=placement,
                signer_name=session.name,
                stamp_info=stamp_info,
                use_visual_overlay=True,
            )
            logger.info(f"PAdES signing completed: profile={pades_audit.signature_profile if pades_audit else 'N/A'}")
        except PlacementValidationError as e:
            logger.warning(f"Invalid placement: code={e.code}, message={e.message}")
            raise ValidationException(f"{e.message} (code: {e.code})")
        except SigningError as e:
            raise SigningException(str(e))

        # Compute final hash AFTER stamp is added (correct order!)
        final_hash = compute_file_hash(local_signed)

        # Upload signed PDF
        signed_gcs_path = (
            f"{session.workspace_id}/{session.document_id}/signed/"
            f"{uuid.uuid4()}_signed.pdf"
        )
        gcs.upload_from_file(local_signed, signed_gcs_path, "application/pdf")

        # Update document
        await supabase.update_document(
            document_id=session.document_id,
            workspace_id=session.workspace_id,
            updates={"gcs_signed_path": signed_gcs_path},
        )

        # Update signer status
        await supabase.update_signer(
            signer_id=session.signer_id,
            workspace_id=session.workspace_id,
            updates={
                "status": SignerStatus.SIGNED.value,
                "signed_at": signed_at.isoformat(),
            },
        )

        # Update signing session with verification data, hash, and PAdES info
        session_updates = {
            "verification_id": verification_id,
            "signed_at": signed_at.isoformat(),
            "final_hash": final_hash,
            "signature_placement": {
                "page": placement.page,
                "x": placement.x,
                "y": placement.y,
                "w": placement.w,
                "h": placement.h,
            },
        }
        # Add PAdES audit info if available
        if pades_audit:
            session_updates["pades_info"] = {
                "signature_profile": pades_audit.signature_profile,
                "kms_key_version": pades_audit.kms_key_version,
                "tsa_url": pades_audit.tsa_url,
                "document_hash_before": pades_audit.document_sha256_before,
                "document_hash_after": pades_audit.document_sha256_after,
            }
        supabase.update_signing_session(
            session_id=session.id,
            updates=session_updates,
        )

        # TODO: Add SIGNED to DB events_type_chk constraint
        logger.info(f"Signer {session.signer_id} signed document, verification_id: {verification_id}")

        # Check if all signers have signed
        is_complete = supabase.check_all_signed(session.document_id)

        # Generate download URL for signed PDF
        signed_pdf_url = gcs.generate_download_signed_url(
            signed_gcs_path,
            expiration_minutes=settings.gcs_signed_url_expiration_minutes,
            filename=f"{doc_data.get('name', 'document')}_signed.pdf",
        )

        # Build response
        response = SignResponse(
            success=True,
            signed_pdf_url=signed_pdf_url,
            signed_at=signed_at,
            is_document_complete=is_complete,
            message="Document signed successfully",
        )

        # Store response for idempotent replay
        supabase.store_signing_response(
            session_id=str(session.id),
            response_data=response.model_dump(mode="json"),
        )

        logger.info(
            f"sign_document: success, session_fp={session_fp}, "
            f"verification_id={verification_id[:8] if verification_id else 'N/A'}..., complete={is_complete}"
        )

        return response

    finally:
        # Cleanup
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")


# =============================================================================
# Verification Endpoints (Public)
# =============================================================================


@app.get(
    "/v1/verify/{verification_id}",
    response_model=VerifyResponse,
    tags=["verification"],
)
async def verify_signature(
    request: Request,
    verification_id: str = Path(..., description="Verification ID from stamp"),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Public endpoint to verify a signed document.

    Users can scan the QR code or enter the verification ID to check
    if the document was signed through this system.

    Rate limited to 10 requests per minute per IP.
    """
    # Rate limiting by IP address
    rate_limiter = get_verify_rate_limiter()
    client_ip = get_client_ip(request)
    allowed, retry_after = rate_limiter.is_allowed(f"verify:{client_ip}")
    if not allowed:
        raise RateLimitException(retry_after, "Too many verification requests. Please try again later.")

    # Look up signing session by verification_id
    result = supabase.table("signing_sessions").select(
        "*, document_signers(name, email)"
    ).eq("verification_id", verification_id).maybeSingle().execute()

    if not result.data:
        return VerifyResponse(
            valid=False,
            verification_id=verification_id,
            status="not_found",
            message="Verification ID not found. The document may not have been signed through this system.",
        )

    session = result.data
    signer_data = session.get("document_signers", {})

    # Check if document was actually signed
    if not session.get("signed_at"):
        return VerifyResponse(
            valid=False,
            verification_id=verification_id,
            document_id=session.get("document_id"),
            status="pending",
            message="This signing session exists but the document has not been signed yet.",
        )

    return VerifyResponse(
        valid=True,
        verification_id=verification_id,
        document_id=session.get("document_id"),
        signer_name=signer_data.get("name"),
        signed_at=session.get("signed_at"),
        verification_method=session.get("otp_channel"),
        status="valid",
        message="Document signature verified. To verify file integrity, use POST /v1/verify/{id}/hash with your PDF's SHA-256 hash.",
    )


@app.post(
    "/v1/verify/{verification_id}/hash",
    response_model=VerifyHashResponse,
    tags=["verification"],
)
async def verify_document_hash(
    request: Request,
    verification_id: str = Path(..., description="Verification ID from stamp"),
    request_body: VerifyHashRequest = ...,
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Verify that a PDF file matches the expected hash for a signed document.

    Users upload their PDF or compute its SHA-256 hash and submit it here
    to verify the document hasn't been modified since signing.

    Rate limited to 10 requests per minute per IP.
    """
    # Rate limiting by IP address
    rate_limiter = get_verify_rate_limiter()
    client_ip = get_client_ip(request)
    allowed, retry_after = rate_limiter.is_allowed(f"verify:{client_ip}")
    if not allowed:
        raise RateLimitException(retry_after, "Too many verification requests. Please try again later.")

    # Look up signing session
    result = supabase.table("signing_sessions").select(
        "final_hash, signed_at"
    ).eq("verification_id", verification_id).maybeSingle().execute()

    if not result.data:
        raise NotFoundError("Verification ID", verification_id)

    session = result.data
    expected_hash = session.get("final_hash")

    if not expected_hash:
        raise ValidationException("Document has not been signed yet")

    # Normalize hashes for comparison (lowercase)
    provided_hash = request_body.file_hash.lower().strip()
    expected_hash = expected_hash.lower().strip()

    matches = provided_hash == expected_hash

    return VerifyHashResponse(
        matches=matches,
        verification_id=verification_id,
        expected_hash=expected_hash,
        provided_hash=provided_hash,
        message="Document hash matches - file is authentic and unmodified."
        if matches
        else "Document hash does NOT match - file may have been modified after signing.",
    )


# Run with uvicorn
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=True,
    )
