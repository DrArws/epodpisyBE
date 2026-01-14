"""
Public Signing API Router - v2 endpoints matching FE contract.
Paths: /v1/signing/sessions/{token}
"""
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, Path, Response
from fastapi.responses import JSONResponse

from app.config import get_settings, Settings
from app.auth import (
    get_signing_session_from_token,
    get_client_ip,
    AuthenticationError,
    AuthorizationError,
)
from app.models import (
    SigningSession,
    SignerStatus,
    OTPStatus,
    OTPChannel,
    SignField,
    SigningSessionResponse,
    SigningErrorCode,
    SigningErrorResponse,
    ERROR_CODE_ALIASES,
    OtpSendRequestV2,
    OtpSendResponseV2,
    OtpVerifyRequestV2,
    OtpVerifyResponseV2,
    SignCompleteRequest,
    SignCompleteResponse,
    SignedStatusResponse,
)
from app.gcs import get_gcs_client, GCSClient
from app.supabase_client import get_supabase_client, SupabaseClient
from app.otp import get_otp_service, OTPService
from app.utils.logging import set_context, get_logger
from app.utils.datetime_utils import utc_now, parse_db_timestamp, is_expired
from app.utils.security import hash_signing_token
logger = get_logger(__name__)

router = APIRouter(
    prefix="/v1/signing/sessions",
    tags=["signing"],
)


def mask_email(email: Optional[str]) -> Optional[str]:
    """Mask email: john@example.com -> j***@example.com"""
    if not email or "@" not in email:
        return None
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        return f"*@{domain}"
    return f"{local[0]}***@{domain}"


def mask_phone(phone: Optional[str]) -> Optional[str]:
    """Mask phone: +420123456789 -> ***6789 (last 4 digits)"""
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
    verification_method: Optional[str] = None,
    otp_locked_until: Optional[str] = None,
) -> OTPStatus:
    """Determine OTP status from session state."""
    # Check if account is locked due to too many failed attempts
    if otp_locked_until:
        locked = parse_db_timestamp(otp_locked_until)
        if locked and locked > utc_now():
            return OTPStatus.LOCKED
    # If verification_method is explicitly "none", OTP is not required
    if verification_method == "none":
        return OTPStatus.NOT_REQUIRED
    # If no phone, OTP cannot be sent
    if not has_phone:
        return OTPStatus.NOT_REQUIRED
    # Check verification status
    if otp_verified_at:
        return OTPStatus.VERIFIED
    if otp_channel:
        return OTPStatus.SENT
    return OTPStatus.REQUIRED


def signing_error_response(
    status_code: int,
    code: SigningErrorCode,
    message: str,
    **kwargs,
) -> JSONResponse:
    """Create a standardized error response."""
    content = SigningErrorResponse(
        code=code,
        message=message,
        **kwargs,
    ).model_dump(exclude_none=True)
    return JSONResponse(status_code=status_code, content=content)


@router.get(
    "/{token}",
    response_model=SigningSessionResponse,
    responses={
        404: {"model": SigningErrorResponse, "description": "Token not found"},
        409: {"model": SigningErrorResponse, "description": "Already signed"},
        410: {"model": SigningErrorResponse, "description": "Token expired"},
    },
)
async def get_signing_session(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    settings: Settings = Depends(get_settings),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Get signing session metadata.

    This endpoint NEVER returns 500 - all errors return structured responses.
    """
    try:
        session = await get_signing_session_from_token(token, request, settings)
        set_context(document_id=session.document_id, signer_id=session.signer_id)

        # Get document data (use admin proxy for public endpoint)
        doc_data = await supabase.get_document_for_signing_admin(session.document_id)
        if not doc_data:
            logger.warning(f"Document {session.document_id} not found")
            return signing_error_response(
                404,
                SigningErrorCode.SIGN_LINK_INVALID,
                "Tento odkaz pro podpis neexistuje nebo byl zneplatněn.",
            )

        # Get session data for OTP status (use admin proxy for public endpoint)
        session_data = await supabase.get_signing_session_admin(session.token_hash)

        # Generate short-lived PDF URL
        pdf_preview_url = None
        if doc_data.get("gcs_pdf_path") and gcs.blob_exists(doc_data["gcs_pdf_path"]):
            pdf_preview_url = gcs.generate_download_signed_url(
                doc_data["gcs_pdf_path"],
                expiration_minutes=settings.gcs_signed_url_expiration_minutes,
            )

        # Compute expiration
        expires_at = None
        expires_in_seconds = 0
        if session_data and session_data.get("expires_at"):
            try:
                exp_str = session_data["expires_at"]
                if isinstance(exp_str, str):
                    expires_at = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                else:
                    expires_at = exp_str
                # Ensure timezone-aware comparison (handle both naive and aware datetimes)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                expires_in_seconds = max(0, int((expires_at - now).total_seconds()))
            except (ValueError, TypeError) as e:
                logger.warning(f"Could not parse expires_at: {e}")
                expires_at = datetime.now(timezone.utc)

        # Determine if OTP is required based on verification_method
        # "none" = no OTP needed, "sms"/"whatsapp" = OTP required, None = legacy (use phone presence)
        if session.verification_method == "none":
            requires_otp = False
        elif session.verification_method in ("sms", "whatsapp"):
            requires_otp = True
        else:
            # Legacy fallback: require OTP if phone is present
            requires_otp = bool(session.phone)

        # Compute OTP status
        otp_status = compute_otp_status(
            has_phone=bool(session.phone),
            otp_channel=session_data.get("otp_channel") if session_data else None,
            otp_verified_at=session_data.get("otp_verified_at") if session_data else None,
            verification_method=session.verification_method,
            otp_locked_until=session_data.get("otp_locked_until") if session_data else None,
        )

        # Build sign fields from placement defaults or document config
        sign_fields = []
        # Default placement for now - could be stored in document_signers table
        # y=640 places signature in upper area of last page (PDF coords from bottom)
        sign_fields.append(SignField(
            id="sig_1",
            page=doc_data.get("page_count", 1),  # Last page
            x=120,
            y=640,
            w=180,
            h=50,
        ))

        # Update signer to viewed if first view
        if session.status == SignerStatus.PENDING:
            await supabase.update_signer(
                signer_id=session.signer_id,
                workspace_id=session.workspace_id,
                updates={
                    "status": SignerStatus.VIEWED.value,
                    "viewed_at": utc_now().isoformat(),
                },
            )

        logger.info(f"Session validated for signer {session.signer_id}")

        # Format document checksum with sha256: prefix
        raw_hash = doc_data.get("final_hash")
        document_checksum = f"sha256:{raw_hash}" if raw_hash else None

        return SigningSessionResponse(
            status="valid",
            document_name=doc_data.get("name", "Dokument"),
            signer_name=session.name,
            signer_email_masked=mask_email(session.email),
            signer_phone_masked=mask_phone(session.phone),
            expires_at=expires_at,
            expires_in_seconds=expires_in_seconds,
            requires_otp=requires_otp,
            otp_status=otp_status,
            pdf_preview_url=pdf_preview_url,
            page_count=doc_data.get("page_count"),
            sign_fields=sign_fields,
            whatsapp_available=True,
            document_checksum=document_checksum,
        )

    except AuthenticationError as e:
        detail = e.detail if isinstance(e.detail, dict) else {"message": str(e.detail)}
        code = detail.get("code", "AUTH_ERROR")

        if code == "SESSION_EXPIRED":
            return signing_error_response(
                410,
                SigningErrorCode.SIGN_LINK_EXPIRED,
                "Platnost odkazu pro podpis vypršela.",
                expired_at=datetime.now(timezone.utc),
            )
        elif code == "ALREADY_SIGNED":
            # Return 200 with status="completed" instead of 409
            # Try to get signed document info
            try:
                token_hash = hash_signing_token(token)
                session_data = await supabase.get_signing_session_admin(token_hash)
                signer_data = session_data.get("document_signers", {}) if session_data else {}
                doc_data = await supabase.get_document_for_signing_admin(session_data.get("document_id")) if session_data else None

                signed_pdf_url = None
                if doc_data and doc_data.get("gcs_signed_path"):
                    signed_pdf_url = gcs.generate_download_signed_url(
                        doc_data["gcs_signed_path"],
                        expiration_minutes=settings.gcs_signed_url_expiration_minutes,
                        filename=f"{doc_data.get('name', 'document')}_signed.pdf",
                    )

                return SigningSessionResponse(
                    status="completed",
                    document_name=doc_data.get("name", "Dokument") if doc_data else "Dokument",
                    signer_name=signer_data.get("name", "Podepisující"),
                    signer_email_masked=mask_email(signer_data.get("email")),
                    signer_phone_masked=mask_phone(signer_data.get("phone")),
                    signed_pdf_url=signed_pdf_url,
                    signed_at=parse_db_timestamp(signer_data.get("signed_at")),
                )
            except Exception as inner_e:
                logger.warning(f"Could not get signed doc info: {inner_e}")
                # Fallback to minimal completed response
                return SigningSessionResponse(
                    status="completed",
                    document_name="Dokument",
                    signer_name="Podepisující",
                )
        else:
            return signing_error_response(
                404,
                SigningErrorCode.SIGN_LINK_INVALID,
                "Tento odkaz pro podpis neexistuje nebo byl zneplatněn.",
            )

    except AuthorizationError as e:
        # Also return 200 with status="completed" for AuthorizationError
        try:
            token_hash = hash_signing_token(token)
            session_data = await supabase.get_signing_session_admin(token_hash)
            signer_data = session_data.get("document_signers", {}) if session_data else {}
            doc_data = await supabase.get_document_for_signing_admin(session_data.get("document_id")) if session_data else None

            signed_pdf_url = None
            if doc_data and doc_data.get("gcs_signed_path"):
                signed_pdf_url = gcs.generate_download_signed_url(
                    doc_data["gcs_signed_path"],
                    expiration_minutes=settings.gcs_signed_url_expiration_minutes,
                    filename=f"{doc_data.get('name', 'document')}_signed.pdf",
                )

            return SigningSessionResponse(
                status="completed",
                document_name=doc_data.get("name", "Dokument") if doc_data else "Dokument",
                signer_name=signer_data.get("name", "Podepisující"),
                signer_email_masked=mask_email(signer_data.get("email")),
                signer_phone_masked=mask_phone(signer_data.get("phone")),
                signed_pdf_url=signed_pdf_url,
                signed_at=parse_db_timestamp(signer_data.get("signed_at")),
            )
        except Exception as inner_e:
            logger.warning(f"Could not get signed doc info: {inner_e}")
            return SigningSessionResponse(
                status="completed",
                document_name="Dokument",
                signer_name="Podepisující",
            )

    except Exception as e:
        logger.error(f"Unexpected error in get_signing_session: {e}", exc_info=True)
        return signing_error_response(
            500,
            SigningErrorCode.SERVER_ERROR,
            "Něco se pokazilo. Zkuste to znovu.",
        )


@router.post(
    "/{token}/otp/send",
    response_model=OtpSendResponseV2,
    responses={
        404: {"model": SigningErrorResponse},
        410: {"model": SigningErrorResponse},
        429: {"model": SigningErrorResponse},
    },
)
async def send_otp(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    request_body: OtpSendRequestV2 = ...,
    settings: Settings = Depends(get_settings),
    supabase: SupabaseClient = Depends(get_supabase_client),
    otp_service: OTPService = Depends(get_otp_service),
):
    """Send OTP code via SMS or WhatsApp."""
    try:
        session = await get_signing_session_from_token(token, request, settings)
        set_context(document_id=session.document_id, signer_id=session.signer_id)

        # DB-based rate limiting
        allowed, error_msg, retry_after = supabase.check_otp_rate_limit(session.id)
        if not allowed:
            return signing_error_response(
                429,
                SigningErrorCode.OTP_RATE_LIMITED,
                error_msg or "Příliš mnoho pokusů.",
                retry_after_seconds=retry_after or 60,
            )

        if not session.phone:
            return signing_error_response(
                422,
                SigningErrorCode.VALIDATION_ERROR,
                "Telefonní číslo není k dispozici.",
            )

        # Send OTP
        from app.utils.logging import fingerprint
        phone_fp = fingerprint(session.phone)
        logger.info(f"otp_send: channel={request_body.channel.value}, phone_fp={phone_fp}")
        result = await otp_service.send_otp(
            phone=session.phone,
            channel=request_body.channel,
            session_id=session.id,
        )

        if not result.success:
            return signing_error_response(
                500,
                SigningErrorCode.SERVER_ERROR,
                result.message or "Nepodařilo se odeslat kód.",
            )

        # Update session
        supabase.increment_otp_send_count(session.id)
        await supabase.update_signing_session(
            session_id=session.id,
            updates={
                "otp_channel": request_body.channel.value,
                "otp_fallback_used": result.fallback_used,
            },
        )

        return OtpSendResponseV2(
            status="otp_sent",
            channel=request_body.channel,
            retry_after_seconds=60,
        )

    except AuthenticationError:
        return signing_error_response(
            404,
            SigningErrorCode.SIGN_LINK_INVALID,
            "Tento odkaz pro podpis neexistuje nebo byl zneplatněn.",
        )
    except Exception as e:
        logger.error(f"Error sending OTP: {e}", exc_info=True)
        return signing_error_response(
            500,
            SigningErrorCode.SERVER_ERROR,
            "Něco se pokazilo. Zkuste to znovu.",
        )


@router.post(
    "/{token}/otp/verify",
    response_model=OtpVerifyResponseV2,
    responses={
        401: {"model": SigningErrorResponse},
        404: {"model": SigningErrorResponse},
        429: {"model": SigningErrorResponse},
    },
)
async def verify_otp(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    request_body: OtpVerifyRequestV2 = ...,
    settings: Settings = Depends(get_settings),
    supabase: SupabaseClient = Depends(get_supabase_client),
    otp_service: OTPService = Depends(get_otp_service),
):
    """Verify OTP code."""
    try:
        session = await get_signing_session_from_token(token, request, settings)
        set_context(document_id=session.document_id, signer_id=session.signer_id)

        # DB-based verify limit
        allowed, error_msg = supabase.check_otp_verify_limit(session.id)
        if not allowed:
            # Get locked_until from session (use admin proxy for public endpoint)
            session_data = await supabase.get_signing_session_admin(session.token_hash)
            locked_until = session_data.get("otp_locked_until") if session_data else None
            return signing_error_response(
                429,
                SigningErrorCode.OTP_TOO_MANY_ATTEMPTS,
                error_msg or "Příliš mnoho neúspěšných pokusů.",
                locked_until=locked_until,
            )

        # Get OTP channel from session (use admin proxy for public endpoint)
        session_data = await supabase.get_signing_session_admin(session.token_hash)
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
            # Reset attempts and mark verified
            supabase.reset_otp_verify_attempts(session.id)
            verified_at = utc_now()
            await supabase.update_signing_session(
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

            logger.info(f"otp_verify: status=success, signer_id={session.signer_id}")
            return OtpVerifyResponseV2(status="verified")

        else:
            # Increment failed attempts
            supabase.increment_otp_verify_attempts(session.id)
            # Get remaining attempts (use admin proxy for public endpoint)
            session_data = await supabase.get_signing_session_admin(session.token_hash)
            attempts = session_data.get("otp_verify_attempts", 0) if session_data else 0
            remaining = max(0, 5 - attempts)

            return signing_error_response(
                401,
                SigningErrorCode.OTP_INVALID,
                "Zadaný kód není správný.",
                remaining_attempts=remaining,
            )

    except AuthenticationError:
        return signing_error_response(
            404,
            SigningErrorCode.SIGN_LINK_INVALID,
            "Tento odkaz pro podpis neexistuje nebo byl zneplatněn.",
        )
    except Exception as e:
        logger.error(f"Error verifying OTP: {e}", exc_info=True)
        return signing_error_response(
            500,
            SigningErrorCode.SERVER_ERROR,
            "Něco se pokazilo. Zkuste to znovu.",
        )


@router.post(
    "/{token}/complete",
    response_model=SignCompleteResponse,
    responses={
        403: {"model": SigningErrorResponse},
        404: {"model": SigningErrorResponse},
        409: {"model": SignCompleteResponse, "description": "Already signed (idempotent)"},
        422: {"model": SigningErrorResponse},
    },
)
async def complete_signature(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    request_body: SignCompleteRequest = ...,
    settings: Settings = Depends(get_settings),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Complete the signature process.

    Idempotent: If already signed, returns 409 with signed_pdf_url.
    FE should treat 409 as success.
    """
    from app.pdf import get_pdf_signer, StampInfo, generate_verification_id, PlacementValidationError
    from app.pdf.sign import SignaturePlacement, SigningError
    from app.utils.security import compute_file_hash
    from app.services.signing_processor import process_and_finalize_signature

    # Get idempotency key from header or generate from request
    idempotency_key = request.headers.get("Idempotency-Key") or request.headers.get("X-Idempotency-Key")

    session: Optional[SigningSession] = None
    acquired_lock = False

    try:
        session = await get_signing_session_from_token(token, request, settings)
        set_context(document_id=session.document_id, signer_id=session.signer_id)

        session_fp = hashlib.sha256(str(session.id).encode()).hexdigest()[:8]
        idem_key_fp = hashlib.sha256(idempotency_key.encode()).hexdigest()[:8] if idempotency_key else "none"

        session_data = await supabase.get_signing_session_admin(session.token_hash)

        otp_required = (
            session.verification_method != "none" and
            (session.verification_method in ("sms", "whatsapp") or bool(session.phone))
        )

        if otp_required and not session_data.get("otp_verified_at"):
            return signing_error_response(403, SigningErrorCode.OTP_NOT_VERIFIED, "Ověření vypršelo. Prosím ověřte se znovu pomocí kódu.")

        if otp_required and session_data.get("otp_verified_at"):
            otp_verified_at = session_data.get("otp_verified_at")
            if is_expired(otp_verified_at, settings.otp_ttl_seconds):
                logger.info(f"OTP verification expired for session_fp={session_fp}")
                return signing_error_response(403, SigningErrorCode.OTP_NOT_VERIFIED, "Ověření vypršelo. Prosím ověřte se znovu pomocí kódu.")

        acquired, cached_response, reason = await supabase.try_acquire_signing_lock_admin(
            session_id=str(session.id),
            idempotency_key=idempotency_key,
        )
        acquired_lock = acquired

        if not acquired_lock:
            logger.info(f"complete_signature: lock not acquired, reason={reason}, session_fp={session_fp}")

            # IDEMPOTENT_REPLAY: Same Idempotency-Key, return 200 with cached response
            if reason == "IDEMPOTENT_REPLAY" and cached_response:
                logger.info(f"complete_signature: idempotent replay, returning cached response")
                return JSONResponse(status_code=200, content=cached_response)

            # ALREADY_SIGNED: Document was signed (possibly by different request)
            if reason == "ALREADY_SIGNED" or reason == "IDEMPOTENT_REPLAY":
                doc_data = await supabase.get_document_for_signing_admin(session.document_id)
                signed_pdf_url = None
                if doc_data and doc_data.get("gcs_signed_path"):
                    signed_pdf_url = gcs.generate_download_signed_url(
                        doc_data["gcs_signed_path"],
                        expiration_minutes=settings.gcs_signed_url_expiration_minutes,
                        filename=f"{doc_data.get('name', 'document')}_signed.pdf",
                    )
                # Return 200 for idempotent behavior (FE can safely retry)
                return JSONResponse(
                    status_code=200,
                    content=SignCompleteResponse(
                        status="completed",
                        signed_pdf_url=signed_pdf_url,
                        signed_at=session_data.get("signed_at") or datetime.now(timezone.utc),
                        message="Dokument již byl podepsán.",
                    ).model_dump(mode="json"),
                )

            # IN_PROGRESS/RACE_LOST: Concurrent signing attempt - return 409
            if reason in ("IN_PROGRESS", "RACE_LOST"):
                return signing_error_response(409, SigningErrorCode.SIGNING_IN_PROGRESS, "Podepisování již probíhá. Počkejte prosím.")

            return signing_error_response(404, SigningErrorCode.SIGN_LINK_INVALID, "Session nenalezena.")

        logger.info(f"complete_signature: lock acquired, proceeding, session_fp={session_fp}")

        # Delegate to the shared signing processor
        response = await process_and_finalize_signature(
            session=session,
            signature_png_base64=request_body.signature_image_base64,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
        )

        # Store response for idempotent replay
        await supabase.store_signing_response_admin(
            session_id=str(session.id),
            response_data=response.model_dump(mode="json"),
        )
        
        return response

    except (PlacementValidationError, SigningError, AuthenticationError, Exception) as e:
        if acquired_lock and session:
            await supabase.release_signing_lock_admin(str(session.id), success=False)
        
        if isinstance(e, PlacementValidationError):
            logger.warning(f"Invalid placement: code={e.code}, message={e.message}")
            return signing_error_response(422, SigningErrorCode.VALIDATION_ERROR, e.message, placement_error_code=e.code)
        
        if isinstance(e, SigningError):
            return signing_error_response(422, SigningErrorCode.VALIDATION_ERROR, f"Chyba při podepisování: {e}")

        if isinstance(e, AuthenticationError):
            return signing_error_response(404, SigningErrorCode.SIGN_LINK_INVALID, "Tento odkaz pro podpis neexistuje nebo byl zneplatněn.")
        
        logger.error(f"Error completing signature: {e}", exc_info=True)
        return signing_error_response(500, SigningErrorCode.SERVER_ERROR, "Něco se pokazilo. Zkuste to znovu.")


@router.get(
    "/{token}/signed",
    response_model=SignedStatusResponse,
    responses={
        404: {"model": SigningErrorResponse, "description": "Token not found"},
        410: {"model": SigningErrorResponse, "description": "Token expired"},
    },
)
async def get_signed_status(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    settings: Settings = Depends(get_settings),
    gcs: GCSClient = Depends(get_gcs_client),
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    Get signing status and download URL for signed document.

    Use this endpoint to:
    - Poll for completion after async submit (202 response from /complete)
    - Refresh expired download URLs for already signed documents

    Each request generates a fresh signed URL with ~60 min TTL.
    """
    try:
        # First, try to get session data directly by token hash
        # This allows checking status even for already-signed sessions
        token_hash = hash_signing_token(token)
        session_data = await supabase.get_signing_session_admin(token_hash)

        if not session_data:
            return signing_error_response(
                404,
                SigningErrorCode.SIGN_LINK_INVALID,
                "Tento odkaz pro podpis neexistuje nebo byl zneplatněn.",
            )

        # Check if session is expired (and not yet signed)
        expires_at = session_data.get("expires_at")
        signed_at = session_data.get("signed_at")

        if expires_at and not signed_at:
            try:
                if isinstance(expires_at, str):
                    exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                else:
                    exp_dt = expires_at
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp_dt:
                    return signing_error_response(
                        410,
                        SigningErrorCode.SIGN_LINK_EXPIRED,
                        "Platnost odkazu pro podpis vypršela.",
                        expired_at=exp_dt,
                    )
            except (ValueError, TypeError):
                pass

        # Determine status
        verification_id = session_data.get("verification_id")
        final_hash = session_data.get("final_hash")
        document_id = session_data.get("document_id")

        # If signed_at is set, document is signed
        if signed_at:
            # Get document to find signed PDF path
            doc_data = await supabase.get_document_for_signing_admin(document_id) if document_id else None
            signed_pdf_url = None

            if doc_data and doc_data.get("gcs_signed_path"):
                signed_pdf_url = gcs.generate_download_signed_url(
                    doc_data["gcs_signed_path"],
                    expiration_minutes=settings.gcs_signed_url_expiration_minutes,
                    filename=f"{doc_data.get('name', 'document')}_signed.pdf",
                )

            # Parse signed_at
            signed_at_dt = None
            if isinstance(signed_at, str):
                try:
                    signed_at_dt = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
                except ValueError:
                    signed_at_dt = None
            else:
                signed_at_dt = signed_at

            return SignedStatusResponse(
                status="signed",
                signed_document_url=signed_pdf_url,
                document_sha256=final_hash,
                signed_at=signed_at_dt,
                verification_id=verification_id,
            )

        # Check if signing is in progress (has signing_lock but no signed_at)
        signing_lock = session_data.get("signing_lock")
        if signing_lock:
            return SignedStatusResponse(
                status="processing",
            )

        # Not signed and not in progress - return processing (waiting for submission)
        return SignedStatusResponse(
            status="processing",
        )

    except Exception as e:
        logger.error(f"Error getting signed status: {e}", exc_info=True)
        return signing_error_response(
            500,
            SigningErrorCode.SERVER_ERROR,
            "Něco se pokazilo. Zkuste to znovu.",
        )
