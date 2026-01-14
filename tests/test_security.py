"""
Tests for security utilities.
"""
import os
import tempfile
import pytest

from app.utils.security import (
    hash_signing_token,
    generate_signing_token,
    verify_signing_token,
    compute_file_hash,
    compute_bytes_hash,
)


class TestTokenHashing:
    """Tests for signing token hashing."""

    def test_hash_signing_token_deterministic(self, mock_settings, monkeypatch):
        """Same token produces same hash."""
        monkeypatch.setattr("app.utils.security.get_settings", lambda: mock_settings)

        token = "test-token-12345"
        hash1 = hash_signing_token(token)
        hash2 = hash_signing_token(token)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex length

    def test_different_tokens_different_hashes(self, mock_settings, monkeypatch):
        """Different tokens produce different hashes."""
        monkeypatch.setattr("app.utils.security.get_settings", lambda: mock_settings)

        hash1 = hash_signing_token("token-1")
        hash2 = hash_signing_token("token-2")

        assert hash1 != hash2

    def test_generate_signing_token(self, mock_settings, monkeypatch):
        """Generated token and hash are valid."""
        monkeypatch.setattr("app.utils.security.get_settings", lambda: mock_settings)

        plain, hashed = generate_signing_token()

        assert len(plain) > 20  # URL-safe base64
        assert len(hashed) == 64  # SHA-256 hex

    def test_verify_signing_token_valid(self, mock_settings, monkeypatch):
        """Valid token verification returns True."""
        monkeypatch.setattr("app.utils.security.get_settings", lambda: mock_settings)

        plain, hashed = generate_signing_token()
        result = verify_signing_token(plain, hashed)

        assert result is True

    def test_verify_signing_token_invalid(self, mock_settings, monkeypatch):
        """Invalid token verification returns False."""
        monkeypatch.setattr("app.utils.security.get_settings", lambda: mock_settings)

        plain, hashed = generate_signing_token()
        result = verify_signing_token("wrong-token", hashed)

        assert result is False


class TestFileHashing:
    """Tests for file hash computation."""

    def test_compute_file_hash(self, temp_dir):
        """File hash is computed correctly."""
        # Create test file
        test_file = os.path.join(temp_dir, "test.txt")
        with open(test_file, "wb") as f:
            f.write(b"Hello, World!")

        hash_result = compute_file_hash(test_file)

        # Known SHA-256 hash for "Hello, World!"
        expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        assert hash_result == expected

    def test_compute_bytes_hash(self):
        """Bytes hash is computed correctly."""
        data = b"Hello, World!"
        hash_result = compute_bytes_hash(data)

        expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        assert hash_result == expected

    def test_different_content_different_hash(self, temp_dir):
        """Different file content produces different hash."""
        file1 = os.path.join(temp_dir, "file1.txt")
        file2 = os.path.join(temp_dir, "file2.txt")

        with open(file1, "wb") as f:
            f.write(b"Content 1")
        with open(file2, "wb") as f:
            f.write(b"Content 2")

        hash1 = compute_file_hash(file1)
        hash2 = compute_file_hash(file2)

        assert hash1 != hash2


class TestNormalizeStoragePath:
    """Tests for GCS storage path normalization."""

    def test_already_normalized_path(self):
        """Path without prefix passes through unchanged."""
        from app.gcs import normalize_storage_path

        path = "workspace123/doc456/uploads/file.pdf"
        result = normalize_storage_path(path)
        assert result == path

    def test_removes_documents_prefix(self):
        """Removes 'documents/' prefix from path."""
        from app.gcs import normalize_storage_path

        path = "documents/workspace123/doc456/original/file.pdf"
        result = normalize_storage_path(path)
        assert result == "workspace123/doc456/uploads/file.pdf"

    def test_remaps_original_to_uploads(self):
        """Remaps 'original' folder to 'uploads'."""
        from app.gcs import normalize_storage_path

        path = "workspace123/doc456/original/file.pdf"
        result = normalize_storage_path(path)
        assert result == "workspace123/doc456/uploads/file.pdf"

    def test_full_legacy_format_documents(self):
        """Handles full legacy FE format with documents/ prefix."""
        from app.gcs import normalize_storage_path

        path = "documents/ws-abc-123/doc-xyz-789/original/uuid-file.docx"
        result = normalize_storage_path(path)
        assert result == "ws-abc-123/doc-xyz-789/uploads/uuid-file.docx"

    def test_full_legacy_format_workspaces(self):
        """Handles full legacy FE format with workspaces/ prefix."""
        from app.gcs import normalize_storage_path

        path = "workspaces/ws-abc-123/doc-xyz-789/original/uuid-file.docx"
        result = normalize_storage_path(path)
        assert result == "ws-abc-123/doc-xyz-789/uploads/uuid-file.docx"

    def test_full_legacy_format_workspaces_documents(self):
        """Handles legacy format: workspaces/{ws}/documents/{doc}/original/{file}."""
        from app.gcs import normalize_storage_path

        path = "workspaces/ws-abc-123/documents/doc-xyz-789/original/uuid-file.docx"
        result = normalize_storage_path(path)
        assert result == "ws-abc-123/doc-xyz-789/uploads/uuid-file.docx"

    def test_rejects_path_traversal(self):
        """Rejects paths with '..' for security."""
        from app.gcs import normalize_storage_path

        with pytest.raises(ValueError, match="Path traversal"):
            normalize_storage_path("workspace/../etc/passwd")

    def test_rejects_absolute_path(self):
        """Rejects absolute paths for security."""
        from app.gcs import normalize_storage_path

        with pytest.raises(ValueError, match="Absolute paths"):
            normalize_storage_path("/etc/passwd")

    def test_rejects_empty_path(self):
        """Rejects empty paths."""
        from app.gcs import normalize_storage_path

        with pytest.raises(ValueError, match="cannot be empty"):
            normalize_storage_path("")
