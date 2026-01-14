import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime
from typing import Optional

from app.config import get_settings, Settings
from app.gcs import get_gcs_client, GCSClient
from app.supabase_client import get_supabase_client, SupabaseClient
from app.pdf import get_pdf_signer, StampInfo, generate_verification_id, PlacementValidationError
from app.pdf.sign import SignaturePlacement, SigningError
from app.utils.security import compute_file_hash
from app.utils.datetime_utils import utc_now
from app.models import SigningSession, SignerStatus, SignCompleteResponse

logger = logging.getLogger(__name__)


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
                "document_hash_before": pades_audit.document_sha256_before,
                "document_hash_after": pades_audit.document_sha256_after,
            }
        await supabase.update_signing_session(session_id=session.id, updates=session_updates)

        # NOTE: Email notifications are handled by frontend/Edge Function
        # Backend no longer sends emails to avoid duplicates

        # Generate download URL and create response
        signed_pdf_url = gcs.generate_download_signed_url(
            signed_gcs_path,
            expiration_minutes=settings.gcs_signed_url_expiration_minutes,
            filename=f"{doc_data.get('name', 'document')}_signed.pdf",
        )
        
        response = SignCompleteResponse(status="completed", signed_pdf_url=signed_pdf_url, signed_at=signed_at)
        
        logger.info(f"Signature processing complete for session {session.id}")
        
        return response

    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception as e:
            logger.warning(f"Cleanup error in signing processor: {e}")
