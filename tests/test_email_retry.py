"""
Tests for email retry logic.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from app.email import (
    EmailService,
    EmailResult,
    EmailDeliveryStatus,
    EmailAttempt,
    MAX_RETRY_ATTEMPTS,
    RETRY_DELAYS_SECONDS,
)


@pytest.fixture
def email_service():
    """Create email service with mocked settings."""
    with patch("app.email.get_settings") as mock_settings:
        settings = MagicMock()
        settings.resend_api_key = "test_api_key"
        settings.resend_from_email = "test@example.com"
        mock_settings.return_value = settings
        service = EmailService(settings=settings)
        return service


@pytest.fixture
def mock_httpx_client():
    """Create mock httpx client."""
    return AsyncMock(spec=httpx.AsyncClient)


class TestEmailRetryLogic:
    """Test retry logic in send_email()."""

    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self, email_service):
        """Email succeeds on first attempt - no retries needed."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "msg_123"}

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = await email_service.send_email(
                to_email="test@test.com",
                subject="Test",
                html="<p>Test</p>",
            )

        assert result.success is True
        assert result.delivery_status == EmailDeliveryStatus.SENT
        assert result.message_id == "msg_123"
        assert result.total_attempts == 1
        assert len(result.attempts) == 1
        assert result.attempts[0].success is True

    @pytest.mark.asyncio
    async def test_fail_twice_succeed_third(self, email_service):
        """Email fails twice, succeeds on third attempt."""
        fail_response = MagicMock()
        fail_response.status_code = 500
        fail_response.text = "Internal Server Error"

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = {"id": "msg_456"}

        call_count = 0

        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return fail_response
            return success_response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.post = mock_post
            mock_client_class.return_value = mock_client

            # Patch asyncio.sleep to speed up test
            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await email_service.send_email(
                    to_email="test@test.com",
                    subject="Test",
                    html="<p>Test</p>",
                )

        assert result.success is True
        assert result.delivery_status == EmailDeliveryStatus.SENT
        assert result.message_id == "msg_456"
        assert result.total_attempts == 3
        assert len(result.attempts) == 3

        # First two attempts failed
        assert result.attempts[0].success is False
        assert result.attempts[1].success is False
        # Third attempt succeeded
        assert result.attempts[2].success is True

    @pytest.mark.asyncio
    async def test_all_attempts_fail(self, email_service):
        """All 3 attempts fail - returns failed status."""
        fail_response = MagicMock()
        fail_response.status_code = 503
        fail_response.text = "Service Unavailable"

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.post.return_value = fail_response
            mock_client_class.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await email_service.send_email(
                    to_email="test@test.com",
                    subject="Test",
                    html="<p>Test</p>",
                )

        assert result.success is False
        assert result.delivery_status == EmailDeliveryStatus.FAILED
        assert result.total_attempts == MAX_RETRY_ATTEMPTS
        assert len(result.attempts) == MAX_RETRY_ATTEMPTS
        assert all(not a.success for a in result.attempts)
        assert "503" in result.error

    @pytest.mark.asyncio
    async def test_timeout_triggers_retry(self, email_service):
        """Timeout exception triggers retry."""
        call_count = 0

        async def mock_post(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.TimeoutException("Connection timed out")
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {"id": "msg_789"}
            return response

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.post = mock_post
            mock_client_class.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await email_service.send_email(
                    to_email="test@test.com",
                    subject="Test",
                    html="<p>Test</p>",
                )

        assert result.success is True
        assert result.total_attempts == 3
        assert "Timeout" in result.attempts[0].error
        assert "Timeout" in result.attempts[1].error
        assert result.attempts[2].success is True

    @pytest.mark.asyncio
    async def test_not_configured_returns_skipped(self):
        """Email service not configured returns SKIPPED status."""
        with patch("app.email.get_settings") as mock_settings:
            settings = MagicMock()
            settings.resend_api_key = ""  # Not configured
            mock_settings.return_value = settings
            service = EmailService(settings=settings)

            result = await service.send_email(
                to_email="test@test.com",
                subject="Test",
                html="<p>Test</p>",
            )

        assert result.success is False
        assert result.delivery_status == EmailDeliveryStatus.SKIPPED
        assert "not configured" in result.error

    @pytest.mark.asyncio
    async def test_audit_callback_called_on_success(self, email_service):
        """Audit callback is called when email succeeds."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": "msg_audit"}

        audit_callback = AsyncMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.post.return_value = mock_response
            mock_client_class.return_value = mock_client

            result = await email_service.send_email(
                to_email="test@test.com",
                subject="Test",
                html="<p>Test</p>",
                audit_callback=audit_callback,
                context_id="doc_123",
            )

        assert result.success is True
        audit_callback.assert_called_once()
        call_args = audit_callback.call_args
        assert call_args[0][0] == "EMAIL_SENT"
        assert call_args[0][1] == "doc_123"
        assert "message_id" in call_args[0][2]

    @pytest.mark.asyncio
    async def test_audit_callback_called_on_failure(self, email_service):
        """Audit callback is called when all attempts fail."""
        fail_response = MagicMock()
        fail_response.status_code = 500
        fail_response.text = "Error"

        audit_callback = AsyncMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.post.return_value = fail_response
            mock_client_class.return_value = mock_client

            with patch("asyncio.sleep", new_callable=AsyncMock):
                result = await email_service.send_email(
                    to_email="test@test.com",
                    subject="Test",
                    html="<p>Test</p>",
                    audit_callback=audit_callback,
                    context_id="doc_456",
                )

        assert result.success is False
        audit_callback.assert_called_once()
        call_args = audit_callback.call_args
        assert call_args[0][0] == "EMAIL_FAILED"
        assert call_args[0][1] == "doc_456"
        assert call_args[0][2]["total_attempts"] == MAX_RETRY_ATTEMPTS


class TestEmailResultProperties:
    """Test EmailResult helper properties."""

    def test_is_delivered(self):
        """is_delivered returns True for SENT status."""
        result = EmailResult(
            success=True,
            delivery_status=EmailDeliveryStatus.SENT,
        )
        assert result.is_delivered is True
        assert result.is_failed is False

    def test_is_failed(self):
        """is_failed returns True for FAILED status."""
        result = EmailResult(
            success=False,
            delivery_status=EmailDeliveryStatus.FAILED,
        )
        assert result.is_failed is True
        assert result.is_delivered is False

    def test_skipped_is_not_delivered(self):
        """SKIPPED status is not delivered."""
        result = EmailResult(
            success=False,
            delivery_status=EmailDeliveryStatus.SKIPPED,
        )
        assert result.is_delivered is False
        assert result.is_failed is False


class TestRetryConfiguration:
    """Test retry configuration constants."""

    def test_max_retry_attempts(self):
        """MAX_RETRY_ATTEMPTS is 3."""
        assert MAX_RETRY_ATTEMPTS == 3

    def test_retry_delays(self):
        """Retry delays are exponential backoff."""
        assert RETRY_DELAYS_SECONDS == [0, 2, 4]
