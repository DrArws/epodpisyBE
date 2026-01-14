"""
Router for handling OAuth 2.0 callbacks.
"""
import logging
import time
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from google_auth_oauthlib.flow import Flow
from google.auth.exceptions import GoogleAuthError

from app.config import get_settings, Settings
from app.auth import verify_google_id_token

logger = logging.getLogger(__name__)
router = APIRouter()


class GoogleAuthCodeRequest(BaseModel):
    """Request model for the authorization code from the frontend."""
    code: str = Field(..., description="The authorization code obtained from Google sign-in.")
    redirect_uri: str = Field(..., description="The redirect_uri used by the client to obtain the code. Must match the one configured in Google Cloud Console.")


class User(BaseModel):
    """User profile information extracted from the ID token."""
    sub: str
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None


class GoogleAuthResponse(BaseModel):
    """Response model containing the ID token and user info."""
    id_token: str
    expires_at: int
    user: User


@router.post(
    "/v1/auth/google",
    response_model=GoogleAuthResponse,
    tags=["authentication"],
    summary="Exchange Google Auth Code for Tokens",
    description="This public endpoint receives a one-time authorization code from a frontend client, "
                "exchanges it for an ID token with Google, and returns the token along with user info. "
                "The returned ID token can then be used as a Bearer token to authenticate with other "
                "protected API endpoints."
)
async def exchange_google_auth_code(
    request: GoogleAuthCodeRequest,
    settings: Settings = Depends(get_settings),
):
    """
    Handles the server-side part of the OAuth 2.0 Authorization Code Flow.
    """
    try:
        client_config = {
            "web": {
                "client_id": settings.oauth_client_id,
                "client_secret": settings.oauth_client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "redirect_uris": [request.redirect_uri],
            }
        }

        flow = Flow.from_client_config(
            client_config,
            scopes=[
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid",
            ],
            redirect_uri=request.redirect_uri,
        )

        # Exchange the authorization code for credentials
        flow.fetch_token(code=request.code)
        credentials = flow.credentials

        if not credentials or not getattr(credentials, "id_token", None):
            raise HTTPException(
                status_code=502,
                detail="Google token exchange succeeded but no id_token was returned. Check OAuth client type/flow and scopes.",
            )

        # Verify the token to get the payload (and ensure its validity)
        payload = await verify_google_id_token(credentials.id_token, settings)

        # Calculate expiration timestamp
        if getattr(credentials, "expiry", None):
            expires_at = int(credentials.expiry.timestamp())
        else:
            expires_at = int(time.time()) + 3600

        # Create user object
        user_info = User(
            sub=payload["sub"],
            email=payload["email"],
            name=payload.get("name"),
            picture=payload.get("picture"),
        )

        return GoogleAuthResponse(
            id_token=credentials.id_token,
            expires_at=expires_at,
            user=user_info,
        )

    except GoogleAuthError as e:
        logger.error(f"Google Auth Error during code exchange: {e}")
        raise HTTPException(
            status_code=400,
            detail=f"Invalid authorization code or redirect URI mismatch. Error: {e}",
        )
    except Exception as e:
        logger.error(f"Unexpected error during code exchange: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An internal error occurred during authentication.")
