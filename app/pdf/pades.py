"""
PAdES digital signature module using Google Cloud KMS.
Wraps the Java pades-kms-signer for cryptographic PDF signing.
"""
import json
import logging
import os
import subprocess
import tempfile
import shutil
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Path to the Java PAdES signer JAR
PADES_JAR_PATH = os.environ.get(
    "PADES_JAR_PATH",
    "/app/lib/pades-kms-signer.jar"
)

# Fallback for local development
PADES_JAR_PATH_DEV = str(
    Path(__file__).parent.parent.parent / "pades-kms-signer" / "target" / "pades-kms-signer.jar"
)


# Exit codes from Java signer
PADES_EXIT_SUCCESS = 0
PADES_EXIT_USAGE_ERROR = 1
PADES_EXIT_CONFIG_ERROR = 2
PADES_EXIT_KMS_ERROR = 3
PADES_EXIT_TSA_ERROR = 4
PADES_EXIT_PDF_ERROR = 5


@dataclass
class PAdESAuditRecord:
    """Audit record from PAdES signing operation."""
    session_id: str
    document_sha256_before: str
    document_sha256_after: str
    kms_key_version: str
    signing_time_utc: str
    tsa_url: str
    tsa_token_time: Optional[str]
    signer_display_name: str
    signature_profile: str
    certificate_subject: Optional[str]
    certificate_fingerprint: Optional[str]
    trust_model: Optional[str]
    kms_latency_ms: Optional[int]
    tsa_latency_ms: Optional[int]
    tsa_attempts: Optional[int]
    signature_bytes: Optional[int]
    signature_integrity_ok: Optional[bool]
    timestamp_integrity_ok: Optional[bool]
    validation_indication: Optional[str]
    validation_sub_indication: Optional[str]
    success: bool
    errors: list


class PAdESSigningError(Exception):
    """PAdES signing operation failed."""
    def __init__(self, message: str, audit: Optional[PAdESAuditRecord] = None):
        super().__init__(message)
        self.audit = audit


class PAdESSigner:
    """
    PAdES digital signature using Google Cloud KMS.

    Creates PAdES-BASELINE-T signatures with:
    - RSA 4096-bit signatures via Cloud KMS
    - RFC3161 timestamps from TSA
    - Self-signed certificate from KMS public key
    """

    def __init__(self, java_path: str = "java", temp_dir: str = "/tmp"):
        """
        Initialize PAdES signer.

        Args:
            java_path: Path to Java executable
            temp_dir: Temporary directory for intermediate files
        """
        self.java_path = java_path
        self.temp_dir = temp_dir
        self.jar_path = self._find_jar()

    def _find_jar(self) -> str:
        """Find the PAdES signer JAR file."""
        # Check configured path first
        if os.path.exists(PADES_JAR_PATH):
            logger.info(f"Using PAdES JAR: {PADES_JAR_PATH}")
            return PADES_JAR_PATH

        # Fallback to development path
        if os.path.exists(PADES_JAR_PATH_DEV):
            logger.info(f"Using development PAdES JAR: {PADES_JAR_PATH_DEV}")
            return PADES_JAR_PATH_DEV

        raise PAdESSigningError(
            f"PAdES signer JAR not found at {PADES_JAR_PATH} or {PADES_JAR_PATH_DEV}"
        )

    def sign_pdf(
        self,
        pdf_path: str,
        signer_name: str,
        output_path: Optional[str] = None,
    ) -> tuple[str, PAdESAuditRecord]:
        """
        Create PAdES digital signature on PDF using Cloud KMS.

        Args:
            pdf_path: Path to input PDF file
            signer_name: Display name of signer (for certificate CN)
            output_path: Optional output path. If None, creates temp file.

        Returns:
            Tuple of (signed_pdf_path, audit_record)

        Raises:
            PAdESSigningError: If signing fails
        """
        if not os.path.exists(pdf_path):
            raise PAdESSigningError(f"Input PDF not found: {pdf_path}")

        # Create working directory
        work_dir = tempfile.mkdtemp(prefix="pades_", dir=self.temp_dir)

        try:
            # Prepare paths
            input_pdf = os.path.join(work_dir, "input.pdf")
            signed_pdf = os.path.join(work_dir, "signed.pdf")
            audit_json = os.path.join(work_dir, "audit.json")

            # Copy input to work dir
            shutil.copy2(pdf_path, input_pdf)

            # Build command
            cmd = [
                self.java_path,
                "-jar", self.jar_path,
                input_pdf,
                signed_pdf,
                signer_name,
            ]

            logger.info(f"Executing PAdES signer: {' '.join(cmd)}")

            # Set up environment with ADC
            env = os.environ.copy()
            # Ensure Google credentials are available
            if "GOOGLE_APPLICATION_CREDENTIALS" not in env:
                adc_path = os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
                if os.path.exists(adc_path):
                    env["GOOGLE_APPLICATION_CREDENTIALS"] = adc_path

            # Run Java signer
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                cwd=work_dir,
                env=env,
            )

            # Log output
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    logger.info(f"[PAdES] {line}")
            if result.stderr:
                for line in result.stderr.strip().split('\n'):
                    logger.warning(f"[PAdES] {line}")

            # Parse audit record
            audit = self._parse_audit(audit_json)

            # Check result with specific error messages based on exit code
            if result.returncode != 0:
                exit_code = result.returncode
                error_type = {
                    PADES_EXIT_USAGE_ERROR: "Usage error",
                    PADES_EXIT_CONFIG_ERROR: "Configuration error (KMS_KEY_NAME)",
                    PADES_EXIT_KMS_ERROR: "KMS error (permission denied or key not found)",
                    PADES_EXIT_TSA_ERROR: "TSA/network error (timestamp server unavailable)",
                    PADES_EXIT_PDF_ERROR: "PDF error (file not found or parse/write error)",
                }.get(exit_code, f"Unknown error (exit code {exit_code})")

                error_msg = f"PAdES signing failed: {error_type}"
                if audit and audit.errors:
                    error_msg += f" - {', '.join(audit.errors)}"
                raise PAdESSigningError(error_msg, audit)

            if not os.path.exists(signed_pdf):
                raise PAdESSigningError("Signed PDF was not created", audit)

            # Move to final output path
            if output_path:
                shutil.move(signed_pdf, output_path)
                final_path = output_path
            else:
                # Create unique output in temp_dir
                import uuid
                final_path = os.path.join(self.temp_dir, f"{uuid.uuid4()}_pades_signed.pdf")
                shutil.move(signed_pdf, final_path)

            logger.info(f"PAdES signing completed: {final_path}")
            logger.info(f"Signature profile: {audit.signature_profile if audit else 'unknown'}")
            logger.info(f"KMS key: {audit.kms_key_version if audit else 'unknown'}")

            return final_path, audit

        except subprocess.TimeoutExpired:
            raise PAdESSigningError("PAdES signing timed out after 120 seconds")
        except FileNotFoundError as e:
            raise PAdESSigningError(f"Java not found or JAR missing: {e}")
        finally:
            # Cleanup work directory
            try:
                shutil.rmtree(work_dir)
            except Exception as e:
                logger.warning(f"Failed to cleanup work dir {work_dir}: {e}")

    def _parse_audit(self, audit_path: str) -> Optional[PAdESAuditRecord]:
        """Parse audit.json from Java signer."""
        if not os.path.exists(audit_path):
            logger.warning("Audit file not found")
            return None

        try:
            with open(audit_path, 'r') as f:
                data = json.load(f)

            return PAdESAuditRecord(
                session_id=data.get("session_id", ""),
                document_sha256_before=data.get("document_sha256_before", ""),
                document_sha256_after=data.get("document_sha256_after", ""),
                kms_key_version=data.get("kms_key_version", ""),
                signing_time_utc=data.get("signing_time_utc", ""),
                tsa_url=data.get("tsa_url", ""),
                tsa_token_time=data.get("tsa_token_time"),
                signer_display_name=data.get("signer_display_name", ""),
                signature_profile=data.get("signature_profile", ""),
                certificate_subject=data.get("certificate_subject"),
                certificate_fingerprint=data.get("certificate_fingerprint"),
                trust_model=data.get("trust_model"),
                kms_latency_ms=data.get("kms_latency_ms"),
                tsa_latency_ms=data.get("tsa_latency_ms"),
                tsa_attempts=data.get("tsa_attempts"),
                signature_bytes=data.get("signature_bytes"),
                signature_integrity_ok=data.get("signature_integrity_ok"),
                timestamp_integrity_ok=data.get("timestamp_integrity_ok"),
                validation_indication=data.get("validation_indication"),
                validation_sub_indication=data.get("validation_sub_indication"),
                success=data.get("success", False),
                errors=data.get("errors", []),
            )
        except Exception as e:
            logger.error(f"Failed to parse audit file: {e}")
            return None

    def is_available(self) -> bool:
        """Check if PAdES signing is available."""
        try:
            # Check JAR exists
            if not os.path.exists(self.jar_path):
                return False

            # Check Java is available
            result = subprocess.run(
                [self.java_path, "-version"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0

        except Exception:
            return False


# Singleton instance
_pades_signer: Optional[PAdESSigner] = None


def get_pades_signer() -> PAdESSigner:
    """Get the PAdES signer singleton."""
    global _pades_signer
    if _pades_signer is None:
        _pades_signer = PAdESSigner()
    return _pades_signer


def is_pades_available() -> bool:
    """Check if PAdES signing is available."""
    try:
        signer = get_pades_signer()
        return signer.is_available()
    except Exception:
        return False
