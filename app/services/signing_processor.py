import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime
from typing import Optional, Dict, List

import httpx

from app.config import get_settings, Settings
from app.gcs import get_gcs_client, GCSClient
from app.supabase_client import get_supabase_client, SupabaseClient
from app.pdf import get_pdf_signer, StampInfo, generate_verification_id, PlacementValidationError
from app.pdf.sign import SignaturePlacement, SigningError
from app.utils.security import compute_file_hash
from app.utils.datetime_utils import utc_now
from app.models import SigningSession, SignerStatus, SignCompleteResponse, EmailTemplateContext
from app.email import get_email_service, EmailService

logger = logging.getLogger(__name__)


async def send_signing_notification_emails(
    document_id: str,
    workspace_id: str,
    signer_name: str,
    signed_at: datetime,
    document_name: str,
    is_all_signed: bool,
    signed_pdf_url: Optional[str] = None,
) -> None:
    """
    Send notification emails after a signature is completed.

    - DOCUMENT_SIGNED: Always sent to document owner when someone signs
    - ALL_SIGNED: Sent to all signers when document is fully signed

    These emails use templates configurable in the frontend.
    Errors are logged but do not fail the signing process.
    """
    settings = get_settings()
    supabase = get_supabase_client()
    email_service = get_email_service()

    # Get workspace name for email templates
    try:
        workspace = await supabase.get_workspace_admin(workspace_id)
        workspace_name = workspace.get("name", "Podpisy") if workspace else "Podpisy"
    except Exception as e:
        logger.warning(f"Failed to get workspace name: {e}")
        workspace_name = "Podpisy"

    async with httpx.AsyncClient(base_url=settings.supabase_url) as http_client:
        # 1. DOCUMENT_SIGNED - notify document owner
        try:
            owner_email = await supabase.get_document_owner_email(document_id)
            if owner_email:
                context = EmailTemplateContext(
                    document_name=document_name,
                    workspace_name=workspace_name,
                    signer_name=signer_name,
                    signed_at=signed_at.strftime("%d.%m.%Y %H:%M"),
                )
                result = await email_service.send_signed_notification(
                    to_email=owner_email,
                    context=context,
                    workspace_id=workspace_id,
                    http_client=http_client,
                    document_id=document_id,
                )
                if result.success:
                    logger.info(f"DOCUMENT_SIGNED email sent to owner for document {document_id}")
                else:
                    logger.warning(f"DOCUMENT_SIGNED email failed: {result.error}")
            else:
                logger.warning(f"No owner email found for document {document_id}")
        except Exception as e:
            logger.error(f"Error sending DOCUMENT_SIGNED email: {e}")

        # 2. ALL_SIGNED - notify all signers when document is complete
        if is_all_signed:
            try:
                signers = await supabase.get_all_signers_for_document(document_id)
                context = EmailTemplateContext(
                    document_name=document_name,
                    workspace_name=workspace_name,
                    completed_at=signed_at.strftime("%d.%m.%Y %H:%M"),
                    download_link=signed_pdf_url,
                )

                for signer in signers:
                    signer_email = signer.get("email")
                    if not signer_email:
                        continue

                    try:
                        result = await email_service.send_all_signed_notification(
                            to_email=signer_email,
                            context=context,
                            workspace_id=workspace_id,
                            http_client=http_client,
                            document_id=document_id,
                        )
                        if result.success:
                            logger.info(f"ALL_SIGNED email sent to {signer.get('name')} for document {document_id}")
                        else:
                            logger.warning(f"ALL_SIGNED email failed for {signer.get('name')}: {result.error}")
                    except Exception as e:
                        logger.error(f"Error sending ALL_SIGNED email to {signer.get('name')}: {e}")

                # Also notify the document owner
                try:
                    owner_email = await supabase.get_document_owner_email(document_id)
                    if owner_email:
                        result = await email_service.send_all_signed_notification(
                            to_email=owner_email,
                            context=context,
                            workspace_id=workspace_id,
                            http_client=http_client,
                            document_id=document_id,
                        )
                        if result.success:
                            logger.info(f"ALL_SIGNED email sent to owner for document {document_id}")
                        else:
                            logger.warning(f"ALL_SIGNED email to owner failed: {result.error}")
                except Exception as e:
                    logger.error(f"Error sending ALL_SIGNED email to owner: {e}")

            except Exception as e:
                logger.error(f"Error sending ALL_SIGNED notifications: {e}")


async def process_and_finalize_signature(
    session: SigningSession,
    signature_png_base64: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> SignCompleteResponse:
    """
    Core logic to process a signature, finalize the PDF, and update the database.
    This function is shared between the synchronous and asynchronous signing flows.
    """
    # Get dependencies
    settings: Settings = get_settings()
    gcs: GCSClient = get_gcs_client()
    supabase: SupabaseClient = get_supabase_client()

    temp_dir = tempfile.mkdtemp(prefix="sign_")
    try:
        # Get document and session data
        doc_data = await supabase.get_document_for_signing_admin(session.document_id)
        if not doc_data:
            raise Exception("Document not found while processing signature.")

        session_data = await supabase.get_signing_session_admin(session.token_hash)
        if not session_data:
            raise Exception("Session data not found while processing signature.")

        # Download the current PDF
        current_pdf_path = doc_data.get("gcs_signed_path") or doc_data.get("gcs_pdf_path")
        if not current_pdf_path:
            raise SigningError("Document has no PDF to sign.")

        local_pdf = os.path.join(temp_dir, "current.pdf")
        gcs.download_to_file(current_pdf_path, local_pdf)

        # Prepare for signing
        verification_id = generate_verification_id()
        verify_url = f"{settings.app_base_url}/verify/{verification_id}"
        placement = SignaturePlacement(page=doc_data.get("page_count", 1), x=120, y=640, w=180, h=50)

        phone_masked = None
        if session.phone and len(session.phone) > 6:
            phone_masked = session.phone[:4] + "***" + session.phone[-3:]
        elif session.phone:
            phone_masked = "***"

        signed_at = utc_now()
        stamp_info = StampInfo(
            verification_id=verification_id,
            verify_url=verify_url,
            signer_name=session.name,
            signed_at=signed_at,
            document_id=session.document_id,
            verification_method=session_data.get("otp_channel"),
            phone_masked=phone_masked,
            include_qr=True,
        )

        # Sign the PDF
        signer = get_pdf_signer()
        local_signed, pades_audit = signer.sign_pdf_pades(
            pdf_path=local_pdf,
            signature_png_base64=signature_png_base64,
            placement=placement,
            signer_name=session.name,
            stamp_info=stamp_info,
            use_visual_overlay=True,
        )
        logger.info(f"PAdES signing completed: profile={pades_audit.signature_profile if pades_audit else 'N/A'}")

        # Upload the signed PDF
        final_hash = compute_file_hash(local_signed)
        signed_gcs_path = f"{session.workspace_id}/{session.document_id}/signed/{uuid.uuid4()}_signed.pdf"
        gcs.upload_from_file(local_signed, signed_gcs_path, "application/pdf")

        # Update database records
        await supabase.update_document(
            document_id=session.document_id,
            workspace_id=session.workspace_id,
            updates={
                "gcs_signed_path": signed_gcs_path,
                "status": "completed",
                "completed_at": signed_at.isoformat(),
            },
        )
        await supabase.update_signer(
            signer_id=session.signer_id,
            workspace_id=session.workspace_id,
            updates={"status": SignerStatus.SIGNED.value, "signed_at": signed_at.isoformat()},
        )

        session_updates = {
            "verification_id": verification_id,
            "signed_at": signed_at.isoformat(),
            "final_hash": final_hash,
            "signing_started_at": None,
            "used_at": signed_at.isoformat(),
            "used_by_ip": ip_address,
            "used_user_agent": user_agent[:500] if user_agent else None,
            "signature_placement": {"page": placement.page, "x": placement.x, "y": placement.y, "w": placement.w, "h": placement.h},
        }
        if pades_audit:
            session_updates["pades_info"] = {
                "signature_profile": pades_audit.signature_profile,
                "kms_key_version": pades_audit.kms_key_version,
                "tsa_url": pades_audit.tsa_url,
                "tsa_url_used": pades_audit.tsa_url_used,
                "tsa_fallback_url": pades_audit.tsa_fallback_url,
                "tsa_fallback_used": pades_audit.tsa_fallback_used,
                "tsa_qualified": pades_audit.tsa_qualified,
                "tsa_applied": pades_audit.tsa_applied,
                "tsa_error_type": pades_audit.tsa_error_type,
                "tsa_error_message": pades_audit.tsa_error_message,
                "document_hash_before": pades_audit.document_sha256_before,
                "document_hash_after": pades_audit.document_sha256_after,
                # Validation results
                "signature_integrity_ok": pades_audit.signature_integrity_ok,
                "timestamp_integrity_ok": pades_audit.timestamp_integrity_ok,
                "validation_indication": pades_audit.validation_indication,
                "validation_sub_indication": pades_audit.validation_sub_indication,
                # Certificate info
                "certificate_subject": pades_audit.certificate_subject,
                "certificate_fingerprint": pades_audit.certificate_fingerprint,
                "trust_model": pades_audit.trust_model,
                # Metrics
                "kms_latency_ms": pades_audit.kms_latency_ms,
                "tsa_latency_ms": pades_audit.tsa_latency_ms,
                "tsa_attempts": pades_audit.tsa_attempts,
                "signature_bytes": pades_audit.signature_bytes,
                "errors": pades_audit.errors,
                "warnings": pades_audit.warnings,
            }
        await supabase.update_signing_session(session_id=session.id, updates=session_updates)

        # Generate download URL and create response
        signed_pdf_url = gcs.generate_download_signed_url(
            signed_gcs_path,
            expiration_minutes=settings.gcs_signed_url_expiration_minutes,
            filename=f"{doc_data.get('name', 'document')}_signed.pdf",
        )

        # Check if all signers have signed
        pending_count = await supabase.get_pending_signers_count(session.document_id)
        is_all_signed = pending_count == 0

        # Send email notifications (DOCUMENT_SIGNED to owner, ALL_SIGNED if complete)
        # Errors are logged but do not fail the signing process
        try:
            await send_signing_notification_emails(
                document_id=session.document_id,
                workspace_id=session.workspace_id,
                signer_name=session.name,
                signed_at=signed_at,
                document_name=doc_data.get("name", "Dokument"),
                is_all_signed=is_all_signed,
                signed_pdf_url=signed_pdf_url,
            )
        except Exception as e:
            logger.error(f"Email notification error (non-fatal): {e}")

        response = SignCompleteResponse(status="completed", signed_pdf_url=signed_pdf_url, signed_at=signed_at)

        logger.info(f"Signature processing complete for session {session.id}")
        
        return response

    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Cleanup error in signing processor: {e}")
