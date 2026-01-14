"""
Custom exceptions and error handlers.
"""
import logging
from typing import Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.utils.logging import get_request_id

logger = logging.getLogger(__name__)


def _get_cors_origin(request: Request) -> Optional[str]:
    """Get CORS origin from request if it's an allowed origin."""
    origin = request.headers.get("origin")
    if not origin:
        return None

    # Allow these origins
    allowed = [
        "https://drbacon.cz",
        "https://podpisy.lovable.app",
    ]

    # Check exact match
    if origin in allowed:
        return origin

    # Allow any *.lovableproject.com subdomain
    if origin.endswith(".lovableproject.com"):
        return origin

    # Allow localhost for development
    if origin.startswith("http://localhost:"):
        return origin

    return None


def _add_cors_headers(response: JSONResponse, request: Request) -> JSONResponse:
    """Add CORS headers to error response."""
    origin = _get_cors_origin(request)
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    return response


class AppException(HTTPException):
    """Base application exception."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Optional[dict] = None,
    ):
        self.code = code
        self.message = message
        self.details = details
        super().__init__(status_code=status_code, detail=message)


class NotFoundError(AppException):
    """Resource not found."""

    def __init__(self, resource: str, resource_id: str):
        super().__init__(
            status_code=404,
            code="NOT_FOUND",
            message=f"{resource} not found: {resource_id}",
        )


class ValidationException(AppException):
    """Validation error."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(
            status_code=400,
            code="VALIDATION_ERROR",
            message=message,
            details=details,
        )


class ConversionException(AppException):
    """PDF conversion error."""

    def __init__(self, message: str):
        super().__init__(
            status_code=422,
            code="CONVERSION_ERROR",
            message=message,
        )


class SigningException(AppException):
    """Signing operation error."""

    def __init__(self, message: str):
        super().__init__(
            status_code=422,
            code="SIGNING_ERROR",
            message=message,
        )


class OTPException(AppException):
    """OTP operation error."""

    def __init__(self, message: str, code: str = "OTP_ERROR"):
        super().__init__(
            status_code=400,
            code=code,
            message=message,
        )


class RateLimitException(AppException):
    """Rate limit exceeded."""

    def __init__(self, retry_after: int, message: Optional[str] = None):
        super().__init__(
            status_code=429,
            code="RATE_LIMIT_EXCEEDED",
            message=message or f"Too many requests. Please try again in {retry_after} seconds.",
            details={"retry_after": retry_after},
        )


def build_error_response(
    status_code: int,
    code: str,
    message: str,
    details: Optional[dict] = None,
) -> dict:
    """Build standardized error response."""
    response = {
        "error": True,
        "code": code,
        "message": message,
        "request_id": get_request_id(),
    }
    if details:
        response["details"] = details
    return response


async def app_exception_handler(
    request: Request,
    exc: AppException,
) -> JSONResponse:
    """Handle application exceptions."""
    logger.warning(f"AppException: {exc.code} - {exc.message}")
    response = JSONResponse(
        status_code=exc.status_code,
        content=build_error_response(
            exc.status_code,
            exc.code,
            exc.message,
            exc.details,
        ),
    )
    return _add_cors_headers(response, request)


async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    """Handle HTTP exceptions."""
    logger.warning(f"HTTPException: {exc.status_code} - {exc.detail}")

    # Extract code and message from detail if structured
    if isinstance(exc.detail, dict):
        code = exc.detail.get("code", "HTTP_ERROR")
        message = exc.detail.get("message", str(exc.detail))
    else:
        code = "HTTP_ERROR"
        message = str(exc.detail)

    response = JSONResponse(
        status_code=exc.status_code,
        content=build_error_response(exc.status_code, code, message),
    )
    return _add_cors_headers(response, request)


async def validation_exception_handler(
    request: Request,
    exc: ValidationError,
) -> JSONResponse:
    """Handle Pydantic validation errors."""
    logger.warning(f"ValidationError: {exc.errors()}")

    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })

    response = JSONResponse(
        status_code=422,
        content=build_error_response(
            422,
            "VALIDATION_ERROR",
            "Request validation failed",
            {"errors": errors},
        ),
    )
    return _add_cors_headers(response, request)


async def generic_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Handle unexpected exceptions."""
    logger.exception(f"Unexpected error: {exc}")

    response = JSONResponse(
        status_code=500,
        content=build_error_response(
            500,
            "INTERNAL_ERROR",
            "An unexpected error occurred",
        ),
    )
    return _add_cors_headers(response, request)
