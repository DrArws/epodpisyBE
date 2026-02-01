"""
NIA (Národní identitní autorita) Router.

Public endpoints for NIA SAML2/eIDAS identity verification in signing flow.

Endpoints:
  POST /v1/signing/sessions/{token}/nia/start  - Initiate NIA authentication
  POST /v1/nia/acs                              - SAML Assertion Consumer Service (callback)
"""
import hashlib
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Path, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.config import get_settings, Settings
from app.auth import (
    get_signing_session_from_token,
    get_client_ip,
    AuthenticationError,
)
from app.models import (
    SigningSession,
    SigningErrorCode,
    SigningErrorResponse,
    NiaStartResponse,
    NiaErrorCode,
)
from app.nia.saml import NIASamlService, SAMLValidationError, get_nia_service
from app.supabase_client import get_supabase_client, SupabaseClient
from app.utils.logging import set_context, get_logger, fingerprint
from app.utils.datetime_utils import utc_now

logger = get_logger(__name__)


# Router for /v1/signing/sessions/{token}/nia/* endpoints
router = APIRouter(
    prefix="/v1/signing/sessions",
    tags=["signing", "nia"],
)

# Separate router for ACS callback (different prefix)
acs_router = APIRouter(
    prefix="/v1/nia",
    tags=["nia"],
)


def _nia_error_response(
    status_code: int,
    code: str,
    message: str,
) -> JSONResponse:
    """Create NIA error response."""
    return JSONResponse(
        status_code=status_code,
        content={
            "error": True,
            "code": code,
            "message": message,
        },
    )


@router.post(
    "/{token}/nia/start",
    response_model=NiaStartResponse,
    responses={
        400: {"description": "NIA disabled or misconfigured"},
        404: {"model": SigningErrorResponse, "description": "Token not found"},
        409: {"description": "Already verified via NIA"},
    },
)
async def start_nia_authentication(
    request: Request,
    token: str = Path(..., description="Signing session token"),
    settings: Settings = Depends(get_settings),
    supabase: SupabaseClient = Depends(get_supabase_client),
    nia_service: NIASamlService = Depends(get_nia_service),
):
    """
    Initiate NIA identity verification.

    Generates a SAML AuthnRequest and returns the NIA redirect URL.
    The signer's browser should be redirected to this URL.

    After successful NIA authentication, the browser will be POST-redirected
    back to our ACS endpoint (/v1/nia/acs).
    """
    try:
        # Check NIA is enabled
        if not settings.nia_enabled:
            return _nia_error_response(
                400,
                NiaErrorCode.NIA_DISABLED,
                "NIA ověření není aktivní.",
            )

        # Validate signing session
        session = await get_signing_session_from_token(token, request, settings)
        set_context(document_id=session.document_id, signer_id=session.signer_id)

        # Check if already verified via NIA
        session_data = await supabase.get_signing_session_admin(session.token_hash)
        if session_data and session_data.get("identity_verified_at") and session_data.get("identity_method") == "nia":
            return _nia_error_response(
                409,
                NiaErrorCode.NIA_ALREADY_VERIFIED,
                "Identita již byla ověřena přes NIA.",
            )

        # Generate random state (CSRF token) - UUID, single-use
        nia_state = str(uuid.uuid4())

        # Build RelayState: encode session_id + state (not the plaintext token!)
        # Format: "session_id:nia_state" - both are internal IDs, not secrets
        relay_state = f"{session.id}:{nia_state}"

        # Store nia_state in signing_sessions for validation in ACS callback
        await supabase.update_signing_session(
            session_id=session.id,
            updates={
                "nia_state": nia_state,
                "identity_method": "nia",
            },
        )

        # Generate SAML AuthnRequest redirect URL
        redirect_url = nia_service.create_authn_request_redirect_url(
            relay_state=relay_state,
        )

        state_fp = hashlib.sha256(nia_state.encode()).hexdigest()[:8]
        logger.info(
            f"nia_start: session_id={session.id}, state_fp={state_fp}, "
            f"signer_id={session.signer_id}"
        )

        return NiaStartResponse(
            redirect_url=redirect_url,
            state=nia_state,
        )

    except AuthenticationError:
        return _nia_error_response(
            404,
            SigningErrorCode.SIGN_LINK_INVALID,
            "Tento odkaz pro podpis neexistuje nebo byl zneplatněn.",
        )
    except Exception as e:
        logger.error(f"nia_start: unexpected error: {e}", exc_info=True)
        return _nia_error_response(
            500,
            SigningErrorCode.SERVER_ERROR,
            "Něco se pokazilo. Zkuste to znovu.",
        )


@acs_router.post(
    "/acs",
    include_in_schema=True,
    summary="NIA SAML Assertion Consumer Service",
)
async def nia_acs_callback(
    request: Request,
    SAMLResponse: str = Form(...),
    RelayState: str = Form(default=""),
    settings: Settings = Depends(get_settings),
    supabase: SupabaseClient = Depends(get_supabase_client),
    nia_service: NIASamlService = Depends(get_nia_service),
):
    """
    SAML Assertion Consumer Service (ACS) endpoint.

    Receives POST form with SAMLResponse and RelayState from NIA IdP
    after successful authentication. Validates the assertion and updates
    the signing session with verified identity.

    Redirects the user back to the signing page in the frontend.
    """
    # Parse RelayState to find the signing session
    # Format: "session_id:nia_state"
    try:
        parts = RelayState.split(":", 1)
        if len(parts) != 2:
            raise ValueError("Invalid RelayState format")
        session_id, nia_state = parts
    except (ValueError, AttributeError) as e:
        logger.warning(f"nia_acs: invalid RelayState format: {e}")
        return _nia_error_response(
            400,
            NiaErrorCode.NIA_STATE_INVALID,
            "Neplatný stav relace (RelayState).",
        )

    try:
        # Look up signing session by ID
        session_data = await supabase.admin_select(
            "signing_sessions",
            columns="*, document_signers(*)",
            filters={"id": f"eq.{session_id}"},
            single=True,
        )

        if not session_data:
            logger.warning(f"nia_acs: session not found for id={session_id}")
            return _nia_error_response(
                404,
                NiaErrorCode.NIA_SESSION_NOT_FOUND,
                "Podpisová relace nenalezena.",
            )

        # Validate nia_state matches (CSRF protection + replay prevention)
        stored_state = session_data.get("nia_state")
        if not stored_state or stored_state != nia_state:
            state_fp = hashlib.sha256(nia_state.encode()).hexdigest()[:8]
            logger.warning(f"nia_acs: state mismatch, state_fp={state_fp}")
            return _nia_error_response(
                400,
                NiaErrorCode.NIA_STATE_INVALID,
                "Neplatný stav relace. Zkuste proces znovu.",
            )

        # Check if already verified (replay protection)
        if session_data.get("identity_verified_at"):
            logger.info(f"nia_acs: already verified, session_id={session_id}")
            # Not an error - redirect to FE (idempotent)
            return _redirect_to_signing_page(settings, session_data, success=True)

        set_context(
            document_id=session_data.get("document_id"),
            signer_id=session_data.get("signer_id"),
        )

        # Validate SAML Response
        result = await nia_service.validate_saml_response(
            saml_response_b64=SAMLResponse,
            relay_state=RelayState,
            expected_relay_state=RelayState,  # We already validated state above
        )

        subject = result["subject"]
        attributes = result["attributes"]
        loa = result.get("loa")
        authn_instant = result.get("authn_instant")

        now = utc_now()
        subject_fp = hashlib.sha256(subject.encode()).hexdigest()[:8]

        # Update signing session with NIA identity
        await supabase.update_signing_session(
            session_id=session_id,
            updates={
                "identity_method": "nia",
                "identity_verified_at": now.isoformat(),
                "nia_subject": subject,
                "nia_loa": loa,
                "nia_attributes": attributes,
                "nia_authn_instant": authn_instant.isoformat() if authn_instant else None,
                # Clear nia_state to prevent replay
                "nia_state": None,
            },
        )

        # Update signer status to VERIFIED
        signer_id = session_data.get("signer_id")
        workspace_id = session_data.get("workspace_id")
        if signer_id and workspace_id:
            await supabase.update_signer(
                signer_id=signer_id,
                workspace_id=workspace_id,
                updates={"status": "verified"},
            )

        # Log audit event
        document_id = session_data.get("document_id")
        if document_id and workspace_id:
            # Mask sensitive attributes for logging
            safe_attrs = {}
            if "givenname" in attributes:
                safe_attrs["given_name_initial"] = attributes["givenname"][:1] + "***"
            if "surname" in attributes:
                safe_attrs["surname_initial"] = attributes["surname"][:1] + "***"
            if loa:
                safe_attrs["loa"] = loa

            await supabase.admin_insert(
                "document_events",
                {
                    "document_id": document_id,
                    "workspace_id": workspace_id,
                    "signer_id": signer_id,
                    "event_type": "IDENTITY_VERIFIED",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("User-Agent", "")[:500],
                    "metadata": {
                        "method": "nia",
                        "loa": loa,
                        "subject_fp": subject_fp,
                        **safe_attrs,
                    },
                },
            )

        logger.info(
            f"nia_acs: identity verified, session_id={session_id}, "
            f"subject_fp={subject_fp}, loa={loa}"
        )

        # Redirect back to signing page
        return _redirect_to_signing_page(settings, session_data, success=True)

    except SAMLValidationError as e:
        logger.warning(f"nia_acs: SAML validation failed: {e.message}, code={e.code}")
        return _redirect_to_signing_page_error(settings, session_id, e.code)

    except Exception as e:
        logger.error(f"nia_acs: unexpected error: {e}", exc_info=True)
        return _redirect_to_signing_page_error(settings, session_id, "NIA_ERROR")


def _redirect_to_signing_page(
    settings: Settings,
    session_data: dict,
    success: bool,
) -> RedirectResponse:
    """
    Redirect user back to the frontend signing page after NIA authentication.

    The frontend will call GET /v1/signing/sessions/{token} and see
    identity_status.verified=true.
    """
    # We can't include the plaintext token in the redirect (we only have hash).
    # The frontend must store the token before redirecting to NIA.
    # We redirect to a generic NIA success page that the FE handles.
    base_url = settings.get_sign_app_url()
    document_id = session_data.get("document_id", "")
    signer_id = session_data.get("signer_id", "")

    if success:
        redirect_url = f"{base_url}/nia/callback?status=success&doc={document_id}"
    else:
        redirect_url = f"{base_url}/nia/callback?status=error&doc={document_id}"

    return RedirectResponse(url=redirect_url, status_code=303)


def _redirect_to_signing_page_error(
    settings: Settings,
    session_id: str,
    error_code: str,
) -> RedirectResponse:
    """Redirect to frontend with error indication."""
    base_url = settings.get_sign_app_url()
    redirect_url = f"{base_url}/nia/callback?status=error&code={error_code}"
    return RedirectResponse(url=redirect_url, status_code=303)
