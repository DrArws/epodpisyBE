"""
Tests for OTP service.
"""
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime, timedelta

from app.otp.twilio_verify import OTPService, OTPChannel, OTPResult


class TestOTPService:
    """Tests for OTP service."""

    @pytest.fixture
    def otp_service(self, mock_settings, monkeypatch):
        """Create OTP service with mock settings."""
        monkeypatch.setattr("app.otp.twilio_verify.get_settings", lambda: mock_settings)
        return OTPService(mock_settings)

    def test_format_phone_with_plus(self, otp_service):
        """Phone with + prefix is unchanged."""
        result = otp_service._format_phone("+420123456789")
        assert result == "+420123456789"

    def test_format_phone_without_prefix(self, otp_service):
        """Phone without prefix gets +420."""
        result = otp_service._format_phone("123456789")
        assert result == "+420123456789"

    def test_format_phone_with_leading_zero(self, otp_service):
        """Phone with leading 0 is converted."""
        result = otp_service._format_phone("0123456789")
        assert result == "+420123456789"

    def test_format_phone_with_double_zero(self, otp_service):
        """Phone with 00 prefix is converted."""
        result = otp_service._format_phone("00420123456789")
        assert result == "+420123456789"

    def test_generate_otp_length(self, otp_service):
        """Generated OTP is 6 digits."""
        otp = otp_service._generate_otp()
        assert len(otp) == 6
        assert otp.isdigit()

    def test_hash_otp_deterministic(self, otp_service):
        """Same phone+code produces same hash."""
        hash1 = otp_service._hash_otp("+420123456789", "123456")
        hash2 = otp_service._hash_otp("+420123456789", "123456")
        assert hash1 == hash2

    def test_hash_otp_different_codes(self, otp_service):
        """Different codes produce different hashes."""
        hash1 = otp_service._hash_otp("+420123456789", "123456")
        hash2 = otp_service._hash_otp("+420123456789", "654321")
        assert hash1 != hash2

    @pytest.mark.asyncio
    async def test_send_otp_sms_success(self, otp_service):
        """SMS OTP send success."""
        # Mock Twilio client
        mock_verification = MagicMock()
        mock_verification.sid = "verification-sid"

        mock_service = MagicMock()
        mock_service.verifications.create.return_value = mock_verification

        mock_verify = MagicMock()
        mock_verify.v2.services.return_value = mock_service

        otp_service._client = MagicMock()
        otp_service._client.verify = mock_verify

        result = await otp_service.send_otp(
            phone="+420123456789",
            channel=OTPChannel.SMS,
            session_id="session-123",
        )

        assert result.success is True
        assert result.sid == "verification-sid"
        assert result.channel == OTPChannel.SMS

    @pytest.mark.asyncio
    async def test_verify_otp_success(self, otp_service):
        """OTP verification success via Verify API."""
        # Mock Twilio client
        mock_check = MagicMock()
        mock_check.status = "approved"
        mock_check.sid = "check-sid"

        mock_service = MagicMock()
        mock_service.verification_checks.create.return_value = mock_check

        mock_verify = MagicMock()
        mock_verify.v2.services.return_value = mock_service

        otp_service._client = MagicMock()
        otp_service._client.verify = mock_verify

        result = await otp_service.verify_otp(
            phone="+420123456789",
            code="123456",
            channel=OTPChannel.SMS,
            session_id="session-123",
            fallback_used=False,
        )

        assert result.success is True
        assert "verified" in result.message.lower()

    @pytest.mark.asyncio
    async def test_verify_otp_invalid_code(self, otp_service):
        """OTP verification fails for invalid code."""
        # Mock Twilio client
        mock_check = MagicMock()
        mock_check.status = "pending"  # Not approved

        mock_service = MagicMock()
        mock_service.verification_checks.create.return_value = mock_check

        mock_verify = MagicMock()
        mock_verify.v2.services.return_value = mock_service

        otp_service._client = MagicMock()
        otp_service._client.verify = mock_verify

        result = await otp_service.verify_otp(
            phone="+420123456789",
            code="000000",
            channel=OTPChannel.SMS,
            session_id="session-123",
            fallback_used=False,
        )

        assert result.success is False
        assert "invalid" in result.message.lower()

    @pytest.mark.asyncio
    async def test_whatsapp_fallback_verify(self, otp_service):
        """WhatsApp fallback OTP verification."""
        # Store a fallback OTP
        phone = "+420123456789"
        code = "123456"
        session_id = "session-123"

        otp_hash = otp_service._hash_otp(phone, code)
        otp_service._stored_otps[session_id] = {
            "hash": otp_hash,
            "phone": phone,
            "expires_at": datetime.utcnow() + timedelta(minutes=10),
        }

        # Verify
        result = await otp_service._verify_local(phone, code, session_id)

        assert result.success is True
        # OTP should be removed after successful verification
        assert session_id not in otp_service._stored_otps

    @pytest.mark.asyncio
    async def test_whatsapp_fallback_expired(self, otp_service):
        """WhatsApp fallback OTP expired."""
        phone = "+420123456789"
        code = "123456"
        session_id = "session-123"

        otp_hash = otp_service._hash_otp(phone, code)
        otp_service._stored_otps[session_id] = {
            "hash": otp_hash,
            "phone": phone,
            "expires_at": datetime.utcnow() - timedelta(minutes=1),  # Expired
        }

        result = await otp_service._verify_local(phone, code, session_id)

        assert result.success is False
        assert "expired" in result.message.lower()

    def test_cleanup_expired_otps(self, otp_service):
        """Cleanup removes expired OTPs."""
        # Add some OTPs
        otp_service._stored_otps["expired"] = {
            "hash": "hash1",
            "phone": "+1",
            "expires_at": datetime.utcnow() - timedelta(minutes=1),
        }
        otp_service._stored_otps["valid"] = {
            "hash": "hash2",
            "phone": "+2",
            "expires_at": datetime.utcnow() + timedelta(minutes=10),
        }

        removed = otp_service.cleanup_expired_otps()

        assert removed == 1
        assert "expired" not in otp_service._stored_otps
        assert "valid" in otp_service._stored_otps
