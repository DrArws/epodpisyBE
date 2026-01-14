"""
Tests for PDF signing.
"""
import os
import pytest
from unittest.mock import MagicMock

import fitz  # PyMuPDF

from app.pdf.sign import PDFSigner, SignaturePlacement, SigningError


class TestPDFSigner:
    """Tests for PDF signing functionality."""

    @pytest.fixture
    def pdf_signer(self, temp_dir):
        """Create PDF signer with temp directory."""
        return PDFSigner(temp_dir=temp_dir)

    @pytest.fixture
    def sample_pdf(self, temp_dir):
        """Create a simple test PDF."""
        pdf_path = os.path.join(temp_dir, "test.pdf")

        # Create a simple PDF with PyMuPDF
        doc = fitz.open()
        page = doc.new_page(width=595, height=842)  # A4 size

        # Add some text
        page.insert_text((50, 100), "Test Document", fontsize=24)
        page.insert_text((50, 150), "This is a test PDF for signing.", fontsize=12)

        doc.save(pdf_path)
        doc.close()

        return pdf_path

    def test_decode_signature_valid(self, pdf_signer, sample_png_base64):
        """Valid PNG signature is decoded."""
        data = pdf_signer._decode_signature(sample_png_base64)
        assert data[:8] == b'\x89PNG\r\n\x1a\n'

    def test_decode_signature_with_data_url(self, pdf_signer, sample_png_base64):
        """PNG with data URL prefix is decoded."""
        data_url = f"data:image/png;base64,{sample_png_base64}"
        data = pdf_signer._decode_signature(data_url)
        assert data[:8] == b'\x89PNG\r\n\x1a\n'

    def test_decode_signature_invalid(self, pdf_signer):
        """Invalid signature raises error."""
        with pytest.raises(SigningError):
            pdf_signer._decode_signature("not-valid-base64!")

    def test_sign_pdf_success(self, pdf_signer, sample_pdf, sample_png_base64):
        """PDF is signed successfully."""
        placement = SignaturePlacement(
            page=1,
            x=100,
            y=100,
            w=150,
            h=50,
        )

        result_path = pdf_signer.sign_pdf(
            pdf_path=sample_pdf,
            signature_png_base64=sample_png_base64,
            placement=placement,
            signer_name="Test User",
        )

        assert os.path.exists(result_path)

        # Verify the signed PDF is valid
        doc = fitz.open(result_path)
        assert doc.page_count == 1
        doc.close()

    def test_sign_pdf_invalid_page(self, pdf_signer, sample_pdf, sample_png_base64):
        """Invalid page number raises error."""
        placement = SignaturePlacement(
            page=99,  # PDF only has 1 page
            x=100,
            y=100,
            w=150,
            h=50,
        )

        with pytest.raises(SigningError) as exc_info:
            pdf_signer.sign_pdf(
                pdf_path=sample_pdf,
                signature_png_base64=sample_png_base64,
                placement=placement,
                signer_name="Test User",
            )

        # Error message is in Czech: "Stránka X neexistuje"
        assert "neexistuje" in str(exc_info.value) or "page" in str(exc_info.value).lower()

    def test_get_page_dimensions(self, pdf_signer, sample_pdf):
        """Page dimensions are retrieved correctly."""
        dims = pdf_signer.get_page_dimensions(sample_pdf, page_num=1)

        assert "width" in dims
        assert "height" in dims
        assert dims["width"] == pytest.approx(595, rel=0.01)  # A4 width
        assert dims["height"] == pytest.approx(842, rel=0.01)  # A4 height

    def test_sign_pdf_preserves_content(self, pdf_signer, sample_pdf, sample_png_base64):
        """Signing preserves original PDF content."""
        placement = SignaturePlacement(
            page=1,
            x=100,
            y=100,
            w=150,
            h=50,
        )

        # Get original text
        doc_before = fitz.open(sample_pdf)
        text_before = doc_before[0].get_text()
        doc_before.close()

        # Sign
        result_path = pdf_signer.sign_pdf(
            pdf_path=sample_pdf,
            signature_png_base64=sample_png_base64,
            placement=placement,
            signer_name="Test User",
        )

        # Get text after signing
        doc_after = fitz.open(result_path)
        text_after = doc_after[0].get_text()
        doc_after.close()

        # Original text should still be present
        assert "Test Document" in text_after
        assert "test PDF for signing" in text_after
