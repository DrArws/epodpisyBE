"""
Twilio OTP service with Verify API and WhatsApp Messaging API fallback.

Strategy:
1. Sandbox mode: Use demo endpoint for testing (no real SMS)
2. SMS: Use Twilio Verify API (preferred)
3. WhatsApp: Try Verify API first, fall back to Messaging API if not available
"""
import logging
import secrets
import hashlib
import httpx
from datetime import datetime, timedelta
from typing import Optional, Tuple
from enum import Enum

from app.config import get_settings, Settings
from app.utils.logging import mask_phone

logger = logging.getLogger(__name__)

# Sandbox demo endpoint
TWILIO_SANDBOX_URL = "https://timberwolf-mastiff-9776.twil.io/demo-reply"


class OTPChannel(str, Enum):
    SMS = "sms"
    WHATSAPP = "whatsapp"


class OTPResult:
    """Result of OTP operation."""
    def __init__(
        self,
        success: bool,
        message: str,
        sid: Optional[str] = None,
        channel: Optional[OTPChannel] = None,
        fallback_used: bool = False,
    ):
        self.success = success
        self.message = message
        self.sid = sid
        self.channel = channel
        self.fallback_used = fallback_used


class OTPService:
    """
    OTP Service using Twilio Verify API with WhatsApp Messaging fallback.

    Supports sandbox mode for testing without real Twilio credentials.
    Never stores OTP codes in plaintext - only hashed.
    """

    # In-memory storage for OTPs (hashed) - used in sandbox and fallback modes
    _stored_otps: dict = {}
    OTP_EXPIRY_MINUTES = 10

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._client = None
        self._sandbox_mode = not self.settings.twilio_account_sid or not self.settings.twilio_verify_service_sid

    @property
    def is_sandbox(self) -> bool:
        """Check if running in sandbox mode (no Twilio credentials)."""
        return self._sandbox_mode

    @property
    def client(self):
        """Get Twilio client (only in production mode)."""
        if self._sandbox_mode:
            return None

        if self._client is None:
            from twilio.rest import Client
            self._client = Client(
                self.settings.twilio_account_sid,
                self.settings.twilio_auth_token,
            )
        return self._client

    def _format_phone(self, phone: str) -> str:
        """Ensure phone is in E.164 format."""
        phone = phone.strip()
        if not phone.startswith("+"):
            # Assume Czech number if no country code
            if phone.startswith("00"):
                phone = "+" + phone[2:]
            elif phone.startswith("0"):
                phone = "+420" + phone[1:]
            else:
                phone = "+420" + phone
        return phone

    def _hash_otp(self, phone: str, code: str) -> str:
        """Hash OTP code for secure storage."""
        return hashlib.sha256(f"{phone}:{code}".encode()).hexdigest()

    def _generate_otp(self) -> str:
        """Generate a secure 6-digit OTP."""
        return str(secrets.randbelow(900000) + 100000)

    async def send_otp(
        self,
        phone: str,
        channel: OTPChannel,
        session_id: str,
    ) -> OTPResult:
        """
        Send OTP via specified channel.

        Args:
            phone: Phone number (E.164 format)
            channel: OTP channel (sms or whatsapp)
            session_id: Signing session ID for tracking

        Returns:
            OTPResult with success status
        """
        phone = self._format_phone(phone)
        logger.info(f"otp_send: channel={channel.value}, phone={mask_phone(phone)}, sandbox={self.is_sandbox}")

        # Sandbox mode - use demo endpoint
        if self.is_sandbox:
            return await self._send_sandbox(phone, channel, session_id)

        # Production mode
        if channel == OTPChannel.SMS:
            return await self._send_via_verify(phone, "sms")
        else:
            # Try Verify API first for WhatsApp
            result = await self._send_via_verify(phone, "whatsapp")
            if result.success:
                return result

            # Fall back to Messaging API
            logger.info("Verify WhatsApp not available, using Messaging fallback")
            return await self._send_whatsapp_fallback(phone, session_id)

    async def _send_sandbox(
        self,
        phone: str,
        channel: OTPChannel,
        session_id: str,
    ) -> OTPResult:
        """
        Send OTP via sandbox demo endpoint.
        Generates OTP locally and calls demo endpoint for logging.
        """
        try:
            # Generate OTP
            code = self._generate_otp()

            # Store hashed OTP with expiry
            otp_hash = self._hash_otp(phone, code)
            expiry = datetime.utcnow() + timedelta(minutes=self.OTP_EXPIRY_MINUTES)
            self._stored_otps[session_id] = {
                "hash": otp_hash,
                "phone": phone,
                "expires_at": expiry,
            }

            # Call sandbox endpoint (fire and forget, for logging)
            async with httpx.AsyncClient() as client:
                await client.post(
                    TWILIO_SANDBOX_URL,
                    json={
                        "to": phone,
                        "channel": channel.value,
                        "code": code,  # Demo only - never log in production!
                        "session_id": session_id,
                    },
                    timeout=5.0,
                )

            logger.info(f"otp_send_sandbox: channel={channel.value}, phone={mask_phone(phone)}")

            return OTPResult(
                success=True,
                message=f"OTP sent via {channel.value} (sandbox mode)",
                sid=f"sandbox_{session_id}",
                channel=channel,
                fallback_used=True,  # Mark as fallback so verify uses local storage
            )

        except Exception as e:
            logger.error(f"Sandbox OTP error: {e}")
            return OTPResult(
                success=False,
                message=f"Failed to send OTP: {str(e)}",
            )

    async def _send_via_verify(
        self,
        phone: str,
        channel: str,
    ) -> OTPResult:
        """Send OTP via Twilio Verify API (production mode only)."""
        from twilio.base.exceptions import TwilioRestException
        try:
            verification = self.client.verify.v2.services(
                self.settings.twilio_verify_service_sid
            ).verifications.create(
                to=phone,
                channel=channel,
            )

            return OTPResult(
                success=True,
                message="OTP sent successfully",
                sid=verification.sid,
                channel=OTPChannel(channel),
                fallback_used=False,
            )

        except TwilioRestException as e:
            logger.warning(f"Verify API error for {channel}: {e.code} - {e.msg}")

            # Check if it's a channel-not-available error
            if e.code in [60200, 60203, 60205]:  # Various channel unavailable codes
                return OTPResult(
                    success=False,
                    message=f"Channel {channel} not available via Verify",
                )

            # Other errors
            return OTPResult(
                success=False,
                message=f"Failed to send OTP: {e.msg}",
            )

    async def _send_whatsapp_fallback(
        self,
        phone: str,
        session_id: str,
    ) -> OTPResult:
        """
        Send OTP via WhatsApp Messaging API as fallback (production mode only).
        Generates and stores hashed OTP locally.
        """
        from twilio.base.exceptions import TwilioRestException
        try:
            # Generate OTP
            code = self._generate_otp()

            # Store hashed OTP with expiry
            otp_hash = self._hash_otp(phone, code)
            expiry = datetime.utcnow() + timedelta(minutes=self.OTP_EXPIRY_MINUTES)
            self._stored_otps[session_id] = {
                "hash": otp_hash,
                "phone": phone,
                "expires_at": expiry,
            }

            # Send via WhatsApp Messaging API
            message = self.client.messages.create(
                body=f"Váš ověřovací kód pro podpis dokumentu je: {code}\n\nKód je platný {self.OTP_EXPIRY_MINUTES} minut.",
                from_=f"whatsapp:{self.settings.twilio_whatsapp_from}",
                to=f"whatsapp:{phone}",
            )

            logger.info(f"WhatsApp fallback message sent: {message.sid}")

            return OTPResult(
                success=True,
                message="OTP sent via WhatsApp",
                sid=message.sid,
                channel=OTPChannel.WHATSAPP,
                fallback_used=True,
            )

        except TwilioRestException as e:
            logger.error(f"WhatsApp fallback error: {e.code} - {e.msg}")
            return OTPResult(
                success=False,
                message=f"Failed to send WhatsApp message: {e.msg}",
            )

    async def verify_otp(
        self,
        phone: str,
        code: str,
        channel: OTPChannel,
        session_id: str,
        fallback_used: bool = False,
    ) -> OTPResult:
        """
        Verify OTP code.

        Args:
            phone: Phone number (E.164 format)
            code: OTP code entered by user
            channel: OTP channel used
            session_id: Signing session ID
            fallback_used: Whether fallback/sandbox was used

        Returns:
            OTPResult with verification status
        """
        phone = self._format_phone(phone)

        # Sandbox mode or fallback - verify against local storage
        if self.is_sandbox or fallback_used:
            return await self._verify_local(phone, code, session_id)

        return await self._verify_via_verify(phone, code)

    async def _verify_via_verify(
        self,
        phone: str,
        code: str,
    ) -> OTPResult:
        """Verify OTP via Twilio Verify API (production mode only)."""
        from twilio.base.exceptions import TwilioRestException
        try:
            verification_check = self.client.verify.v2.services(
                self.settings.twilio_verify_service_sid
            ).verification_checks.create(
                to=phone,
                code=code,
            )

            if verification_check.status == "approved":
                return OTPResult(
                    success=True,
                    message="OTP verified successfully",
                    sid=verification_check.sid,
                )
            else:
                return OTPResult(
                    success=False,
                    message="Invalid OTP code",
                )

        except TwilioRestException as e:
            logger.warning(f"Verify check error: {e.code} - {e.msg}")

            # Handle specific error codes
            if e.code == 20404:  # Verification not found (expired)
                return OTPResult(
                    success=False,
                    message="OTP expired. Please request a new code.",
                )
            if e.code == 60202:  # Max check attempts reached
                return OTPResult(
                    success=False,
                    message="Too many attempts. Please request a new code.",
                )

            return OTPResult(
                success=False,
                message="Verification failed",
            )

    async def _verify_local(
        self,
        phone: str,
        code: str,
        session_id: str,
    ) -> OTPResult:
        """Verify OTP against local storage (sandbox/fallback mode)."""
        stored = self._stored_otps.get(session_id)

        if not stored:
            return OTPResult(
                success=False,
                message="OTP not found. Please request a new code.",
            )

        # Check expiry
        if datetime.utcnow() > stored["expires_at"]:
            del self._stored_otps[session_id]
            return OTPResult(
                success=False,
                message="OTP expired. Please request a new code.",
            )

        # Verify hash
        expected_hash = self._hash_otp(phone, code)
        if secrets.compare_digest(stored["hash"], expected_hash):
            # Remove used OTP
            del self._stored_otps[session_id]
            return OTPResult(
                success=True,
                message="OTP verified successfully",
            )

        return OTPResult(
            success=False,
            message="Invalid OTP code",
        )

    def cleanup_expired_otps(self) -> int:
        """Remove expired OTPs from local storage. Returns count of removed."""
        now = datetime.utcnow()
        expired = [
            sid for sid, data in self._stored_otps.items()
            if now > data["expires_at"]
        ]
        for sid in expired:
            del self._stored_otps[sid]
        return len(expired)


# Singleton instance
_otp_service: Optional[OTPService] = None


def get_otp_service() -> OTPService:
    """Get the OTP service singleton."""
    global _otp_service
    if _otp_service is None:
        _otp_service = OTPService()
    return _otp_service
