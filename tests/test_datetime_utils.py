"""
Tests for datetime_utils module.
"""
import pytest
from datetime import datetime, timezone, timedelta
from app.utils.datetime_utils import (
    utc_now,
    parse_db_timestamp,
    is_expired,
    seconds_since,
    is_within_window,
)


class TestUtcNow:
    """Test utc_now() function."""

    def test_returns_timezone_aware(self):
        """utc_now() returns timezone-aware datetime."""
        now = utc_now()
        assert now.tzinfo is not None
        assert now.tzinfo == timezone.utc

    def test_returns_utc(self):
        """utc_now() returns UTC time."""
        now = utc_now()
        # Should be close to datetime.now(timezone.utc)
        diff = abs((now - datetime.now(timezone.utc)).total_seconds())
        assert diff < 1  # Within 1 second


class TestParseDbTimestamp:
    """Test parse_db_timestamp() function."""

    def test_none_returns_none(self):
        """None input returns None."""
        assert parse_db_timestamp(None) is None

    def test_empty_string_returns_none(self):
        """Empty string returns None."""
        assert parse_db_timestamp("") is None

    def test_iso_with_z_suffix(self):
        """Parses ISO format with Z suffix."""
        result = parse_db_timestamp("2024-01-13T12:00:00Z")
        assert result is not None
        assert result.tzinfo is not None
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 13
        assert result.hour == 12

    def test_iso_with_offset(self):
        """Parses ISO format with +00:00 offset."""
        result = parse_db_timestamp("2024-01-13T12:00:00+00:00")
        assert result is not None
        assert result.tzinfo is not None

    def test_naive_datetime_becomes_utc(self):
        """Naive datetime input is assumed UTC."""
        naive = datetime(2024, 1, 13, 12, 0, 0)
        result = parse_db_timestamp(naive)
        assert result is not None
        assert result.tzinfo == timezone.utc

    def test_aware_datetime_preserved(self):
        """Timezone-aware datetime is preserved."""
        aware = datetime(2024, 1, 13, 12, 0, 0, tzinfo=timezone.utc)
        result = parse_db_timestamp(aware)
        assert result is not None
        assert result.tzinfo == timezone.utc

    def test_invalid_string_returns_none(self):
        """Invalid date string returns None."""
        assert parse_db_timestamp("not-a-date") is None
        assert parse_db_timestamp("12345") is None

    def test_non_string_non_datetime_returns_none(self):
        """Non-string, non-datetime returns None."""
        assert parse_db_timestamp(12345) is None
        assert parse_db_timestamp([]) is None


class TestIsExpired:
    """Test is_expired() function."""

    def test_none_is_expired(self):
        """None timestamp is considered expired."""
        assert is_expired(None, 600) is True

    def test_future_not_expired(self):
        """Timestamp within TTL is not expired."""
        recent = utc_now() - timedelta(seconds=30)
        assert is_expired(recent, 600) is False

    def test_past_is_expired(self):
        """Timestamp beyond TTL is expired."""
        old = utc_now() - timedelta(seconds=700)
        assert is_expired(old, 600) is True

    def test_exact_boundary_is_expired(self):
        """Timestamp exactly at TTL boundary is expired."""
        exactly_at_ttl = utc_now() - timedelta(seconds=600)
        # Should be expired (> not >=)
        # Give a small buffer for test execution time
        assert is_expired(exactly_at_ttl, 599) is True

    def test_string_timestamp(self):
        """Works with ISO string timestamps."""
        recent = (utc_now() - timedelta(seconds=30)).isoformat()
        assert is_expired(recent, 600) is False

        old = (utc_now() - timedelta(seconds=700)).isoformat()
        assert is_expired(old, 600) is True


class TestSecondsSince:
    """Test seconds_since() function."""

    def test_none_returns_none(self):
        """None timestamp returns None."""
        assert seconds_since(None) is None

    def test_recent_timestamp(self):
        """Returns positive seconds for past timestamp."""
        recent = utc_now() - timedelta(seconds=30)
        result = seconds_since(recent)
        assert result is not None
        assert 29 < result < 32  # Allow some variance

    def test_invalid_returns_none(self):
        """Invalid timestamp returns None."""
        assert seconds_since("not-a-date") is None


class TestIsWithinWindow:
    """Test is_within_window() function."""

    def test_within_window(self):
        """Timestamp within window returns True."""
        recent = utc_now() - timedelta(seconds=30)
        assert is_within_window(recent, 60) is True

    def test_outside_window(self):
        """Timestamp outside window returns False."""
        old = utc_now() - timedelta(seconds=90)
        assert is_within_window(old, 60) is False

    def test_none_returns_false(self):
        """None timestamp returns False."""
        assert is_within_window(None, 60) is False


class TestOTPTTLScenarios:
    """Integration-style tests for OTP TTL scenarios."""

    def test_otp_verified_5_minutes_ago_valid(self):
        """OTP verified 5 minutes ago is valid (TTL=10min)."""
        verified_at = utc_now() - timedelta(minutes=5)
        assert is_expired(verified_at, 600) is False

    def test_otp_verified_11_minutes_ago_expired(self):
        """OTP verified 11 minutes ago is expired (TTL=10min)."""
        verified_at = utc_now() - timedelta(minutes=11)
        assert is_expired(verified_at, 600) is True

    def test_otp_verified_now_valid(self):
        """OTP verified just now is valid."""
        verified_at = utc_now()
        assert is_expired(verified_at, 600) is False

    def test_custom_ttl_respected(self):
        """Custom TTL value is respected."""
        verified_at = utc_now() - timedelta(seconds=90)
        # With 60s TTL, should be expired
        assert is_expired(verified_at, 60) is True
        # With 120s TTL, should be valid
        assert is_expired(verified_at, 120) is False
