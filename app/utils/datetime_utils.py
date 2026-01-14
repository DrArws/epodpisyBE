"""
Timezone-aware datetime utilities.

All datetime operations should use these helpers to ensure consistent
timezone handling across the codebase.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, Union


def utc_now() -> datetime:
    """
    Get current UTC time as timezone-aware datetime.

    Use this instead of datetime.utcnow() which returns naive datetime.
    """
    return datetime.now(timezone.utc)


def parse_db_timestamp(value: Optional[Union[str, datetime]]) -> Optional[datetime]:
    """
    Parse timestamp from database, ensuring timezone-aware UTC.

    Handles:
    - ISO format strings with Z suffix
    - ISO format strings with +00:00 offset
    - Naive datetimes (assumed UTC)
    - Already timezone-aware datetimes

    Args:
        value: Timestamp from database (string or datetime)

    Returns:
        Timezone-aware datetime in UTC, or None if input is None/empty
    """
    if value is None:
        return None

    if isinstance(value, str):
        if not value:
            return None
        # Handle Z suffix (common in PostgreSQL/Supabase)
        value = value.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            # Fallback for other formats
            return None
    elif isinstance(value, datetime):
        dt = value
    else:
        return None

    # Ensure timezone-aware (assume UTC if naive)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def is_expired(timestamp: Optional[Union[str, datetime]], ttl_seconds: int) -> bool:
    """
    Check if timestamp + TTL has passed (i.e., is expired).

    Args:
        timestamp: The timestamp to check
        ttl_seconds: Time-to-live in seconds

    Returns:
        True if expired or timestamp is None, False otherwise
    """
    if timestamp is None:
        return True

    dt = parse_db_timestamp(timestamp)
    if dt is None:
        return True

    expiry = dt + timedelta(seconds=ttl_seconds)
    return utc_now() > expiry


def seconds_since(timestamp: Optional[Union[str, datetime]]) -> Optional[float]:
    """
    Get seconds elapsed since timestamp.

    Args:
        timestamp: The timestamp to measure from

    Returns:
        Seconds since timestamp, or None if timestamp is invalid
    """
    if timestamp is None:
        return None

    dt = parse_db_timestamp(timestamp)
    if dt is None:
        return None

    return (utc_now() - dt).total_seconds()


def is_within_window(
    timestamp: Optional[Union[str, datetime]],
    window_seconds: int
) -> bool:
    """
    Check if timestamp is within the last N seconds.

    Args:
        timestamp: The timestamp to check
        window_seconds: Window size in seconds

    Returns:
        True if timestamp is within window, False otherwise
    """
    elapsed = seconds_since(timestamp)
    if elapsed is None:
        return False
    return elapsed <= window_seconds
