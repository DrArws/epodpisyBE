"""
Configuration module - loads secrets from Google Secret Manager.
Falls back to environment variables for local development.
"""
import os
import logging
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings
from pydantic import Field, model_validator, field_validator
from typing import List, Any

logger = logging.getLogger(__name__)


def get_secret_from_gcp(secret_id: str, project_id: Optional[str] = None) -> Optional[str]:
    """
    Fetch secret from Google Secret Manager.
    Returns None if not available (fallback to env vars).
    """
    try:
        from google.cloud import secretmanager

        client = secretmanager.SecretManagerServiceClient()
        project = project_id or os.environ.get("GCP_PROJECT_ID") or os.environ.get("GOOGLE_CLOUD_PROJECT")

        if not project:
            return None

        name = f"projects/{project}/secrets/{secret_id}/versions/latest"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        logger.debug(f"Could not fetch secret {secret_id} from Secret Manager: {e}")
        return None


class Settings(BaseSettings):
    """Application settings with Secret Manager integration."""

    # GCP
    gcp_project_id: str = Field(default="", alias="GCP_PROJECT_ID")
    oauth_client_id: str = Field(default="", alias="OAUTH_CLIENT_ID")
    oauth_client_secret: str = Field(default="", alias="OAUTH_CLIENT_SECRET")

    # Supabase (using anon key + user JWT for RLS)
    supabase_url: str = Field(default="", alias="SUPABASE_URL")
    supabase_anon_key: str = Field(default="", alias="SUPABASE_ANON_KEY")

    # GCS
    gcs_bucket: str = Field(default="", alias="GCS_BUCKET")
    gcs_signed_url_expiration_minutes: int = Field(default=10, alias="GCS_SIGNED_URL_EXPIRATION_MINUTES")

    # Twilio
    twilio_account_sid: str = Field(default="", alias="TWILIO_ACCOUNT_SID")
    twilio_auth_token: str = Field(default="", alias="TWILIO_AUTH_TOKEN")
    twilio_verify_service_sid: str = Field(default="", alias="TWILIO_VERIFY_SERVICE_SID")
    twilio_whatsapp_from: str = Field(default="", alias="TWILIO_WHATSAPP_FROM")

    # Resend (Email)
    resend_api_key: str = Field(default="", alias="RESEND_API_KEY")
    resend_from_email: str = Field(default="podpis@amlko.cz", alias="RESEND_FROM_EMAIL")

    # App
    app_base_url: str = Field(default="http://localhost:8000", alias="APP_BASE_URL")
    sign_app_url: str = Field(default="", alias="SIGN_APP_URL")
    signing_token_salt: str = Field(default="", alias="SIGNING_TOKEN_SALT")
    admin_api_secret: str = Field(default="", alias="ADMIN_API_SECRET")
    internal_api_secret: str = Field(default="", alias="INTERNAL_API_SECRET")
    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")

    # Rate limiting
    otp_rate_limit_requests: int = Field(default=5, alias="OTP_RATE_LIMIT_REQUESTS")
    otp_rate_limit_window_seconds: int = Field(default=300, alias="OTP_RATE_LIMIT_WINDOW_SECONDS")

    # OTP timing
    otp_ttl_seconds: int = Field(
        default=600,
        alias="OTP_TTL_SECONDS",
        description="How long OTP verification is valid for signing (default 10 min)"
    )
    otp_min_resend_seconds: int = Field(
        default=60,
        alias="OTP_MIN_RESEND_SECONDS",
        description="Minimum seconds between OTP resend requests (default 60s)"
    )

    # Environment
    environment: str = Field(default="development", alias="ENVIRONMENT")
    debug: bool = Field(default=False, alias="DEBUG")

    # CORS
    allowed_origins: List[str] = Field(default=[], alias="ALLOWED_ORIGINS")
    allowed_origin_regex: str = Field(default="", alias="ALLOWED_ORIGIN_REGEX")

    @field_validator("allowed_origins", mode='before')
    @classmethod
    def _parse_allowed_origins(cls, v: Any) -> List[str]:
        if isinstance(v, str) and v:
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        if isinstance(v, list):
            return v
        return []

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._load_secrets_from_gcp()

    def _load_secrets_from_gcp(self):
        """Override settings with values from Secret Manager if available."""
        secret_mappings = {
            "supabase_url": "SUPABASE_URL",
            "supabase_anon_key": "SUPABASE_ANON_KEY",
            "gcs_bucket": "GCS_BUCKET",
            "twilio_account_sid": "TWILIO_ACCOUNT_SID",
            "twilio_auth_token": "TWILIO_AUTH_TOKEN",
            "twilio_verify_service_sid": "TWILIO_VERIFY_SERVICE_SID",
            "twilio_whatsapp_from": "TWILIO_WHATSAPP_FROM",
            "resend_api_key": "RESEND_API_KEY",
            "signing_token_salt": "SIGNING_TOKEN_SALT",
            "admin_api_secret": "ADMIN_API_SECRET",
            "internal_api_secret": "INTERNAL_API_SECRET",
            "oauth_client_id": "OAUTH_CLIENT_ID",
            "oauth_client_secret": "OAUTH_CLIENT_SECRET",
            "gemini_api_key": "GEMINI_API_KEY",
        }

        for attr, secret_id in secret_mappings.items():
            secret_value = get_secret_from_gcp(secret_id, self.gcp_project_id)
            if secret_value:
                setattr(self, attr, secret_value)
                logger.info(f"Loaded {secret_id} from Secret Manager")

    @model_validator(mode='after')
    def validate_urls(self) -> 'Settings':
        """Validate URL configuration for the environment."""
        # Warn if APP_BASE_URL is not HTTPS in production
        if self.environment == "production" and not self.app_base_url.startswith("https://"):
            logger.warning(
                f"Configuration Warning: APP_BASE_URL ('{self.app_base_url}') "
                f"does not start with 'https://' in a '{self.environment}' environment."
            )

        # CRITICAL: Validate SIGN_APP_URL in production
        if self.environment == "production":
            if not self.sign_app_url:
                logger.error(
                    "CRITICAL: SIGN_APP_URL is not set in production! "
                    "Signing links will use APP_BASE_URL which may be incorrect. "
                    "Set SIGN_APP_URL to your frontend domain (e.g., https://sign.arws.cz)"
                )
            elif not self.sign_app_url.startswith("https://"):
                logger.error(
                    f"CRITICAL: SIGN_APP_URL ('{self.sign_app_url}') must use HTTPS in production!"
                )
            elif "localhost" in self.sign_app_url:
                logger.error(
                    f"CRITICAL: SIGN_APP_URL ('{self.sign_app_url}') contains localhost in production!"
                )

        return self

    def get_sign_app_url(self) -> str:
        """
        Get the frontend signing app URL.

        IMPORTANT: This URL is used in signing emails sent to signers.
        It MUST be the publicly accessible frontend URL, not the backend URL.

        Falls back to app_base_url if SIGN_APP_URL not set (development only).
        """
        if self.sign_app_url:
            return self.sign_app_url.rstrip("/")

        # Fallback - only safe in development
        if self.environment != "development":
            logger.warning(
                f"SIGN_APP_URL not set, falling back to APP_BASE_URL ({self.app_base_url}). "
                "This is likely incorrect for production!"
            )
        return self.app_base_url.rstrip("/")




@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Convenience function for dependency injection
def get_config() -> Settings:
    return get_settings()
