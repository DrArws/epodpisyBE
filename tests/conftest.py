"""
Pytest configuration and fixtures.
"""
import os
import sys
import tempfile
from unittest.mock import MagicMock, AsyncMock
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_png_base64():
    """Generate a minimal valid PNG as base64."""
    # Minimal 1x1 transparent PNG
    import base64
    png_bytes = bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1 dimensions
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,  # bit depth, color type
        0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,  # IDAT chunk
        0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
        0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
        0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,  # IEND chunk
        0x42, 0x60, 0x82
    ])
    return base64.b64encode(png_bytes).decode()


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    settings = MagicMock()
    settings.supabase_url = "https://test.supabase.co"
    settings.supabase_jwt_secret = "test-jwt-secret"
    settings.gcs_bucket = "test-bucket"
    settings.gcs_signed_url_expiration_minutes = 10
    settings.twilio_account_sid = "test-sid"
    settings.twilio_auth_token = "test-token"
    settings.twilio_verify_service_sid = "test-verify-sid"
    settings.twilio_whatsapp_from = "+14155238886"
    settings.signing_token_salt = "test-salt"
    settings.environment = "test"
    settings.debug = True
    settings.otp_rate_limit_requests = 5
    settings.otp_rate_limit_window_seconds = 300
    return settings


@pytest.fixture
def mock_supabase():
    """Create mock Supabase client."""
    client = MagicMock()

    # Mock table operations
    table_mock = MagicMock()
    table_mock.select.return_value = table_mock
    table_mock.eq.return_value = table_mock
    table_mock.neq.return_value = table_mock
    table_mock.single.return_value = table_mock
    table_mock.order.return_value = table_mock
    table_mock.execute.return_value = MagicMock(data=[], count=0)

    client.table.return_value = table_mock
    return client


@pytest.fixture
def mock_gcs():
    """Create mock GCS client."""
    client = MagicMock()
    client.generate_upload_signed_url.return_value = (
        "https://storage.googleapis.com/signed-upload-url",
        "workspace/doc/uploads/file.pdf",
        600
    )
    client.generate_download_signed_url.return_value = (
        "https://storage.googleapis.com/signed-download-url"
    )
    client.download_to_file.return_value = "/tmp/downloaded.pdf"
    client.upload_from_file.return_value = "workspace/doc/pdf/file.pdf"
    return client


@pytest.fixture
def sample_signing_session():
    """Create sample signing session data."""
    return {
        "id": "session-123",
        "document_id": "doc-456",
        "signer_id": "signer-789",
        "workspace_id": "ws-000",
        "token_hash": "hashed-token",
        "phone": "+420123456789",
        "email": "signer@example.com",
        "name": "Test Signer",
        "status": "pending",
        "otp_verified_at": None,
        "signed_at": None,
        "viewed_at": None,
        "document_signers": {
            "id": "signer-789",
            "name": "Test Signer",
            "phone": "+420123456789",
            "email": "signer@example.com",
            "status": "pending",
        }
    }


@pytest.fixture
def sample_document():
    """Create sample document data."""
    return {
        "id": "doc-456",
        "workspace_id": "ws-000",
        "name": "Test Document",
        "status": "pending",
        "gcs_original_path": "ws-000/doc-456/uploads/original.docx",
        "gcs_pdf_path": "ws-000/doc-456/pdf/document.pdf",
        "gcs_signed_path": None,
        "gcs_evidence_path": None,
        "page_count": 3,
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "created_by": "user-123",
    }
