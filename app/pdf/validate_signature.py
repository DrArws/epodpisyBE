"""
PDF Signature Validation Utility.

Validates that a signed PDF contains proper PAdES signature structure
that will be recognized by Adobe Acrobat Reader.

Acrobat Validation Checklist:
1. /FT /Sig - Signature field exists
2. /Type /Sig - Signature object present
3. /ByteRange - Data range that was signed
4. /Contents - CMS/PKCS#7 signature blob
5. /SubFilter - Either /adbe.pkcs7.detached or /ETSI.CAdES.detached
"""
import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class SignatureValidationResult:
    """Result of PDF signature structure validation."""
    is_valid: bool
    has_signature_field: bool  # /FT /Sig
    has_signature_object: bool  # /Type /Sig
    has_byte_range: bool  # /ByteRange
    has_contents: bool  # /Contents
    has_sub_filter: bool  # /SubFilter
    sub_filter_value: Optional[str]  # e.g., "adbe.pkcs7.detached"
    signature_count: int
    errors: List[str]
    warnings: List[str]


def validate_pdf_signature_structure(pdf_path: str) -> SignatureValidationResult:
    """
    Validate that a PDF contains proper signature structure for Acrobat.

    This is a structural check only - it doesn't verify cryptographic validity.
    It checks that the PDF contains the elements needed for Acrobat to recognize
    and display the signature panel.

    Args:
        pdf_path: Path to the signed PDF file

    Returns:
        SignatureValidationResult with validation details
    """
    errors = []
    warnings = []

    has_sig_field = False
    has_sig_object = False
    has_byte_range = False
    has_contents = False
    has_sub_filter = False
    sub_filter_value = None
    signature_count = 0

    try:
        # Read PDF as bytes for pattern matching
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        # Convert to string for regex (treating as latin-1 to preserve bytes)
        pdf_text = pdf_bytes.decode("latin-1", errors="replace")

        # Check for signature field (/FT /Sig)
        sig_field_pattern = r"/FT\s*/Sig"
        sig_field_matches = re.findall(sig_field_pattern, pdf_text)
        has_sig_field = len(sig_field_matches) > 0
        signature_count = len(sig_field_matches)

        if not has_sig_field:
            errors.append("No signature field found (/FT /Sig)")
        else:
            logger.info(f"Found {signature_count} signature field(s)")

        # Check for signature object (/Type /Sig)
        sig_obj_pattern = r"/Type\s*/Sig"
        sig_obj_matches = re.findall(sig_obj_pattern, pdf_text)
        has_sig_object = len(sig_obj_matches) > 0

        if not has_sig_object:
            errors.append("No signature object found (/Type /Sig)")

        # Check for ByteRange
        byte_range_pattern = r"/ByteRange\s*\[\s*\d+\s+\d+\s+\d+\s+\d+\s*\]"
        byte_range_matches = re.findall(byte_range_pattern, pdf_text)
        has_byte_range = len(byte_range_matches) > 0

        if not has_byte_range:
            errors.append("No ByteRange found - signature may not be valid")
        else:
            logger.info(f"ByteRange found: {byte_range_matches[0][:50]}...")

        # Check for Contents (hex-encoded CMS blob)
        contents_pattern = r"/Contents\s*<[0-9A-Fa-f]+"
        contents_matches = re.findall(contents_pattern, pdf_text)
        has_contents = len(contents_matches) > 0

        if not has_contents:
            errors.append("No Contents found - no signature blob present")

        # Check for SubFilter
        sub_filter_pattern = r"/SubFilter\s*/([A-Za-z0-9._]+)"
        sub_filter_matches = re.findall(sub_filter_pattern, pdf_text)
        has_sub_filter = len(sub_filter_matches) > 0

        if has_sub_filter:
            sub_filter_value = sub_filter_matches[0]
            logger.info(f"SubFilter: {sub_filter_value}")

            # Check for valid SubFilter values
            valid_sub_filters = [
                "adbe.pkcs7.detached",
                "adbe.pkcs7.sha1",  # Legacy, but valid
                "ETSI.CAdES.detached",  # EU standard
            ]
            if sub_filter_value not in valid_sub_filters:
                warnings.append(f"Unusual SubFilter: {sub_filter_value}")
        else:
            errors.append("No SubFilter found - signature type unknown")

        # Additional checks
        # Check for signature appearance (/AP)
        appearance_pattern = r"/AP\s*<<"
        if not re.search(appearance_pattern, pdf_text):
            warnings.append("No appearance stream (/AP) found - signature may be invisible")

        # Check that signature is properly terminated (no writes after /Contents)
        # This is a heuristic - look for stream objects after the last /Contents
        last_contents_pos = pdf_text.rfind("/Contents")
        if last_contents_pos > 0:
            after_contents = pdf_text[last_contents_pos:]
            # Check for unexpected modifications (new objects)
            if re.search(r"\d+\s+\d+\s+obj\s*<<", after_contents[1000:]):  # Skip signature dict
                warnings.append("Possible modification after signature - integrity may be compromised")

        is_valid = has_sig_field and has_sig_object and has_byte_range and has_contents and has_sub_filter

        return SignatureValidationResult(
            is_valid=is_valid,
            has_signature_field=has_sig_field,
            has_signature_object=has_sig_object,
            has_byte_range=has_byte_range,
            has_contents=has_contents,
            has_sub_filter=has_sub_filter,
            sub_filter_value=sub_filter_value,
            signature_count=signature_count,
            errors=errors,
            warnings=warnings,
        )

    except Exception as e:
        logger.exception("Failed to validate PDF signature structure")
        return SignatureValidationResult(
            is_valid=False,
            has_signature_field=False,
            has_signature_object=False,
            has_byte_range=False,
            has_contents=False,
            has_sub_filter=False,
            sub_filter_value=None,
            signature_count=0,
            errors=[f"Validation failed: {str(e)}"],
            warnings=[],
        )


def print_validation_result(result: SignatureValidationResult) -> None:
    """Print validation result in a readable format."""
    print("\n=== PDF Signature Validation ===")
    print(f"Overall: {'VALID' if result.is_valid else 'INVALID'}")
    print(f"Signature fields found: {result.signature_count}")
    print()
    print("Checklist:")
    print(f"  [{'✓' if result.has_signature_field else '✗'}] Signature Field (/FT /Sig)")
    print(f"  [{'✓' if result.has_signature_object else '✗'}] Signature Object (/Type /Sig)")
    print(f"  [{'✓' if result.has_byte_range else '✗'}] ByteRange")
    print(f"  [{'✓' if result.has_contents else '✗'}] Contents (CMS blob)")
    print(f"  [{'✓' if result.has_sub_filter else '✗'}] SubFilter: {result.sub_filter_value or 'N/A'}")

    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"  ❌ {error}")

    if result.warnings:
        print("\nWarnings:")
        for warning in result.warnings:
            print(f"  ⚠️ {warning}")

    print()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python validate_signature.py <signed.pdf>")
        sys.exit(1)

    pdf_path = sys.argv[1]
    result = validate_pdf_signature_structure(pdf_path)
    print_validation_result(result)

    sys.exit(0 if result.is_valid else 1)
