"""
Google Cloud Storage client module.
Handles signed URLs, uploads, and downloads.
"""
import logging
import os
import uuid
from datetime import timedelta, datetime, timezone
from typing import Optional, Tuple
from pathlib import Path
from urllib.parse import quote

import google.auth
from google.auth import iam
from google.auth.transport.requests import Request
from google.cloud import storage
from google.cloud.storage import Blob

from app.config import get_settings, Settings



logger = logging.getLogger(__name__)





def normalize_storage_path(path: str) -> str:

    """

    Normalize storage path to actual GCS object path.



    Handles legacy FE formats:

      - documents/{ws}/{doc}/original/{file}

      - workspaces/{ws}/documents/{doc}/original/{file}

    Converts to canonical GCS path: {ws}/{doc}/uploads/{file}



    Raises ValueError for path traversal attempts or absolute paths.

    """

    if not path:

        raise ValueError("Storage path cannot be empty")



    # Security: reject path traversal and absolute paths

    if ".." in path:

        raise ValueError("Path traversal not allowed")

    if path.startswith("/"):

        raise ValueError("Absolute paths not allowed")



    original_path = path



    # Handle legacy FE formats

    # Format: documents/{ws}/{doc}/original/{file}

    if path.startswith("documents/"):

        path = path[len("documents/"):]

    # Format: workspaces/{ws}/documents/{doc}/original/{file}

    elif path.startswith("workspaces/"):

        path = path[len("workspaces/"):]

        # Also remove /documents/ segment if present

        path = path.replace("/documents/", "/", 1)



    # Remap "original" folder to "uploads" (the actual GCS folder)

    path = path.replace("/original/", "/uploads/")



    if original_path != path:

        logger.info(f"[PATH NORMALIZED] {original_path} -> {path}")



    return path





def _encode_filename_for_header(filename: str) -> str:

    """

    Encode filename for Content-Disposition header (RFC 5987/RFC 6266).

    Handles Czech and other Unicode characters properly.

    """

    try:

        filename.encode('ascii')

        safe_filename = filename.replace('"', '\\"')

        return f'attachment; filename="{safe_filename}"'

    except UnicodeEncodeError:

        encoded = quote(filename, safe='')

        ascii_fallback = _transliterate_filename(filename)

        return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}"





def _transliterate_filename(filename: str) -> str:

    """Transliterate Czech characters to ASCII for fallback filename."""

    replacements = {

        'á': 'a', 'č': 'c', 'ď': 'd', 'é': 'e', 'ě': 'e',

        'í': 'i', 'ň': 'n', 'ó': 'o', 'ř': 'r', 'š': 's',

        'ť': 't', 'ú': 'u', 'ů': 'u', 'ý': 'y', 'ž': 'z',

        'Á': 'A', 'Č': 'C', 'Ď': 'D', 'É': 'E', 'Ě': 'E',

        'Í': 'I', 'Ň': 'N', 'Ó': 'O', 'Ř': 'R', 'Š': 'S',

        'Ť': 'T', 'Ú': 'U', 'Ů': 'U', 'Ý': 'Y', 'Ž': 'Z',

    }

    result = filename

    for cz, ascii_char in replacements.items():

        result = result.replace(cz, ascii_char)

    return ''.join(c if ord(c) < 128 else '_' for c in result)





class GCSClient:
    """Google Cloud Storage client wrapper."""

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._client: Optional[storage.Client] = None
        self._bucket: Optional[storage.Bucket] = None

    @property
    def client(self) -> storage.Client:
        if self._client is None:
            self._client = storage.Client()
        return self._client

    @property
    def bucket(self) -> storage.Bucket:
        if self._bucket is None:
            self._bucket = self.client.bucket(self.settings.gcs_bucket)
        return self._bucket

    def _generate_iam_signed_url(
        self,
        blob: Blob,
        method: str,
        expiration_delta: timedelta,
        content_type: Optional[str] = None,
        response_disposition: Optional[str] = None,
    ) -> str:
        """
        Generates a V4 signed URL using the runtime service account's identity (IAM).
        This is the recommended way for Cloud Run, App Engine, etc.
        """
        credentials, _ = google.auth.default()
        req = Request()
        credentials.refresh(req)

        return blob.generate_signed_url(
            version="v4",
            expiration=expiration_delta,
            method=method,
            content_type=content_type,
            response_disposition=response_disposition,
            service_account_email=credentials.service_account_email,
            access_token=credentials.token,
        )

    def generate_upload_signed_url(
        self,
        workspace_id: str,
        document_id: str,
        filename: str,
        content_type: str,
        folder: str = "uploads",
    ) -> Tuple[str, str, int]:
        """
        Generate a V4 signed URL for uploading a file using IAM.
        """
        ext = Path(filename).suffix.lower()
        unique_filename = f"{uuid.uuid4()}{ext}"
        # This is the actual path in GCS
        object_path = f"{workspace_id}/{document_id}/{folder}/{unique_filename}"
        
        # This is the path format FE expects for the 'convert' step
        gcs_path_for_fe = f"documents/{workspace_id}/{document_id}/original/{unique_filename}"

        blob = self.bucket.blob(object_path)
        expiration_delta = timedelta(minutes=self.settings.gcs_signed_url_expiration_minutes)

        signed_url = self._generate_iam_signed_url(
            blob=blob,
            method="PUT",
            expiration_delta=expiration_delta,
            content_type=content_type,
        )

        expiration_seconds = int(expiration_delta.total_seconds())

        return signed_url, gcs_path_for_fe, expiration_seconds

    def generate_download_signed_url(
        self,
        gcs_path: str,
        expiration_minutes: Optional[int] = None,
        filename: Optional[str] = None,
    ) -> str:
        """
        Generate a V4 signed URL for downloading a file using IAM.
        """
        blob = self.bucket.blob(gcs_path)
        if not blob.exists():
            raise FileNotFoundError(f"File not found: {gcs_path}")

        expiration_delta = timedelta(
            minutes=expiration_minutes or self.settings.gcs_signed_url_expiration_minutes
        )

        response_disposition = _encode_filename_for_header(filename) if filename else None

        signed_url = self._generate_iam_signed_url(
            blob=blob,
            method="GET",
            expiration_delta=expiration_delta,
            response_disposition=response_disposition,
        )

        return signed_url

    def download_to_file(self, gcs_path: str, local_path: str) -> str:
        """Download a file from GCS to local filesystem."""
        blob = self.bucket.blob(gcs_path)
        if not blob.exists():
            raise FileNotFoundError(f"File not found in GCS: {gcs_path}")
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        blob.download_to_filename(local_path)
        logger.info(f"Downloaded {gcs_path} to {local_path}")
        return local_path

    def upload_from_file(
        self,
        local_path: str,
        gcs_path: str,
        content_type: Optional[str] = None,
    ) -> str:
        """Upload a local file to GCS."""
        blob = self.bucket.blob(gcs_path)
        if content_type:
            blob.content_type = content_type
        blob.upload_from_filename(local_path)
        logger.info(f"Uploaded {local_path} to {gcs_path}")
        return gcs_path
        
    def blob_exists(self, gcs_path: str) -> bool:
        """Check if a blob exists."""
        return self.bucket.blob(gcs_path).exists()

# Singleton instance
_gcs_client: Optional[GCSClient] = None


def get_gcs_client() -> GCSClient:
    """Get the GCS client singleton."""
    global _gcs_client
    if _gcs_client is None:
        _gcs_client = GCSClient()
    return _gcs_client

