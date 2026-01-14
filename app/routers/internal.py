"""
Internal API Router - for service-to-service communication.
Not exposed to the public internet.
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, HTTPException, Header
from pydantic import BaseModel, Field

from app.config import get_settings, Settings
from app.services.signing_processor import process_and_finalize_signature
from app.supabase_client import get_supabase_client, SupabaseClient
from app.models import SigningSession
from app.pdf.sign import SigningError

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/internal/v1",
    tags=["internal"],
)


class ProcessSignatureRequest(BaseModel):
    session_id: str = Field(..., description="The ID of the signing session to process.")


async def verify_internal_secret(
    x_internal_secret: Optional[str] = Header(None),
    settings: Settings = Depends(get_settings),
):
    """Dependency to verify the internal API secret."""
    if not x_internal_secret:
        logger.warning("Internal endpoint called without X-Internal-Secret header")
        raise HTTPException(status_code=401, detail="Unauthorized")

    if x_internal_secret == settings.internal_api_secret:
        logger.info("Internal secret matched")
    else:
        logger.warning("Internal secret mismatch")
        raise HTTPException(status_code=403, detail="Forbidden")


@router.post(
    "/process-signature",
    dependencies=[Depends(verify_internal_secret)],
    summary="Process and finalize a signature asynchronously",
)
async def process_signature(
    request: ProcessSignatureRequest,
    supabase: SupabaseClient = Depends(get_supabase_client),
):
    """
    This endpoint is called internally (e.g., by a Supabase Edge Function)
    to perform the heavy lifting of PDF signing after initial validation
    and signature image upload is complete.
    """
    session_id = request.session_id
    logger.info(f"Internal endpoint /process-signature called for session_id: {session_id}")

    # Idempotency Check 1: Has it already been signed?
    session_data = await supabase.admin_select("signing_sessions", {"id": session_id}, single=True)
    if not session_data:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found.")

    if session_data.get("signed_at"):
        logger.info(f"Session {session_id} already processed (signed_at is set). Skipping.")
        return {"status": "already_processed"}

    acquired_lock = False
    try:
        # Acquire lock - this is an additional safety measure.
        # The Edge Function should have already set signing_started_at.
        lock_acquired, _, reason = await supabase.try_acquire_signing_lock_admin(session_id)
        if not lock_acquired:
             # If lock fails here, it's a conflict. Log and return.
             logger.warning(f"Could not acquire lock for session {session_id} during internal processing. Reason: {reason}")
             raise HTTPException(status_code=409, detail=f"Conflict: could not acquire lock. Reason: {reason}")
        
        acquired_lock = True
        logger.info(f"Lock successfully acquired for session {session_id} during internal processing.")

        # At this point, the Edge Function is expected to have saved the signature image
        # and stored its download URL in the `signing_sessions` table.
        signature_url = session_data.get("signature_image_download_url")
        if not signature_url:
            raise HTTPException(status_code=422, detail=f"Session {session_id} has no signature_image_download_url.")

        # Download signature from the pre-signed URL
        import httpx
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(signature_url)
                response.raise_for_status()
                signature_bytes = response.content
            except httpx.HTTPStatusError as e:
                logger.error(f"Failed to download signature from pre-signed URL {signature_url}: {e}")
                raise HTTPException(status_code=400, detail="Failed to download signature from pre-signed URL.")
        
        # The signature image is stored as raw bytes, but the processor expects base64.
        import base64
        signature_base64 = "data:image/png;base64," + base64.b64encode(signature_bytes).decode('utf-8')
        
        # The processor needs a full SigningSession object, not just the dict.
        # We need to get the associated signer as well.
        full_session_data = await supabase.get_signing_session_admin(session_data['token_hash'])
        if not full_session_data:
             raise HTTPException(status_code=404, detail="Could not retrieve full session details.")
        session = SigningSession(**full_session_data)

        # Call the shared service to do the heavy work
        await process_and_finalize_signature(
            session=session,
            signature_png_base64=signature_base64,
            ip_address=session_data.get("used_by_ip"),
            user_agent=session_data.get("used_user_agent"),
        )

        return {"status": "processed_successfully"}

    except (SigningError, HTTPException) as e:
        # Re-raise known errors to return proper HTTP responses
        logger.error(f"A known error occurred during signature processing for session {session_id}: {e}")
        raise e
    except Exception as e:
        logger.error(f"An unexpected error occurred during signature processing for session {session_id}: {e}", exc_info=True)
        # For any other error, return a generic 500
        raise HTTPException(status_code=500, detail="An unexpected error occurred during signature processing.")

    finally:
        # Bulletproof lock release
        if acquired_lock:
            # Check again to ensure we don't clear a successfully signed session
            # if an error happens during the final return.
            final_session_check = await supabase.admin_select("signing_sessions", {"id": session_id}, single=True)
            if final_session_check and not final_session_check.get("signed_at"):
                logger.warning(f"Releasing lock for session {session_id} in finally block due to failure.")
                await supabase.release_signing_lock_admin(session_id)
            else:
                logger.info(f"Lock for session {session_id} was already released by successful processing.")

