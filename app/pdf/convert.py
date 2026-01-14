"""
PDF conversion module.
- LibreOffice headless for office documents
- Pillow + reportlab for images
- Direct copy/validation for PDFs
"""
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Tuple

import fitz  # PyMuPDF
from PIL import Image
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas

logger = logging.getLogger(__name__)

# Constants
A4_WIDTH_PT = A4[0]  # 595.27 points
A4_HEIGHT_PT = A4[1]  # 841.89 points
A4_WIDTH_MM = 210
A4_HEIGHT_MM = 297
MARGIN_MM = 10

# Supported content types
OFFICE_TYPES = {
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
    "text/plain",
    "text/csv",
}

IMAGE_TYPES = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/tiff",
}


class ConversionError(Exception):
    """PDF conversion error."""
    pass


class PDFConverter:
    """PDF converter with LibreOffice and image support."""

    def __init__(self, temp_dir: str = "/tmp/e-signing"):
        self.temp_dir = temp_dir

    def convert_to_pdf(
        self,
        input_path: str,
        content_type: str,
        original_filename: str,
    ) -> Tuple[str, int]:
        """
        Convert a file to PDF.

        Args:
            input_path: Path to input file
            content_type: MIME type of input
            original_filename: Original filename (for extension detection)

        Returns:
            Tuple of (output_pdf_path, page_count)

        Raises:
            ConversionError: If conversion fails
        """
        if content_type == "application/pdf":
            return self._handle_pdf(input_path)
        elif content_type in OFFICE_TYPES:
            return self._convert_office(input_path, original_filename)
        elif content_type in IMAGE_TYPES:
            return self._convert_image(input_path)
        else:
            raise ConversionError(f"Unsupported content type: {content_type}")

    def _handle_pdf(self, input_path: str) -> Tuple[str, int]:
        """
        Handle PDF input - validate and optionally normalize.
        """
        try:
            # Open and validate PDF
            doc = fitz.open(input_path)
            page_count = doc.page_count

            if page_count == 0:
                raise ConversionError("PDF has no pages")

            # Create a clean copy (normalizes the PDF)
            output_path = os.path.join(
                self.temp_dir,
                f"{uuid.uuid4()}.pdf"
            )

            # Save with garbage collection to clean up
            doc.save(output_path, garbage=4, deflate=True)
            doc.close()

            logger.info(f"Validated PDF with {page_count} pages")
            return output_path, page_count

        except fitz.FileDataError as e:
            raise ConversionError(f"Invalid PDF file: {e}")

    def _convert_office(
        self,
        input_path: str,
        original_filename: str,
    ) -> Tuple[str, int]:
        """
        Convert office document using LibreOffice headless.
        """
        # Verify soffice is available before attempting conversion
        soffice_path = shutil.which("soffice")
        if not soffice_path:
            # Check common paths
            common_paths = [
                "/usr/bin/soffice",
                "/usr/lib/libreoffice/program/soffice",
            ]
            for path in common_paths:
                if os.path.exists(path) and os.access(path, os.X_OK):
                    soffice_path = path
                    break

        if not soffice_path:
            logger.error("LibreOffice (soffice) not found in PATH or common locations")
            raise ConversionError(
                "LibreOffice is not installed or not accessible. "
                "Please check the server configuration."
            )

        # Create unique directories for this conversion
        conversion_id = str(uuid.uuid4())
        output_dir = os.path.join(self.temp_dir, conversion_id)
        # CRITICAL: Use unique user profile to prevent locking between concurrent conversions
        user_profile_dir = os.path.join(self.temp_dir, f"profile_{conversion_id}")
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(user_profile_dir, exist_ok=True)

        try:
            # Run LibreOffice conversion with unique user installation path
            # This prevents profile locking issues in concurrent environments
            cmd = [
                soffice_path,
                "--headless",
                "--invisible",
                "--nologo",
                "--nofirststartwizard",
                "--norestore",
                f"-env:UserInstallation=file://{user_profile_dir}",
                "--convert-to", "pdf:writer_pdf_Export",
                "--outdir", output_dir,
                input_path,
            ]

            logger.info(f"Running LibreOffice conversion: {' '.join(cmd)}")

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=90,  # 90 second timeout (leave buffer for Cloud Run)
                    env={
                        **os.environ,
                        "HOME": user_profile_dir,
                        "TMPDIR": self.temp_dir,
                        # Disable Java which can cause hangs
                        "SAL_USE_VCLPLUGIN": "svp",
                    },
                )
            except FileNotFoundError as e:
                logger.error(f"LibreOffice executable not found: {e}")
                raise ConversionError(
                    f"LibreOffice executable not found: {soffice_path}. "
                    f"Error: {e}"
                )
            except PermissionError as e:
                logger.error(f"Permission denied running LibreOffice: {e}")
                raise ConversionError(
                    f"Permission denied running LibreOffice: {e}"
                )

            if result.returncode != 0:
                logger.error(f"LibreOffice error (exit code {result.returncode}): {result.stderr}")
                # Include both stdout and stderr for debugging
                error_details = result.stderr or result.stdout or "Unknown error"
                raise ConversionError(
                    f"LibreOffice conversion failed (exit code {result.returncode}): {error_details}"
                )

            # Find the output PDF
            pdf_files = list(Path(output_dir).glob("*.pdf"))
            if not pdf_files:
                logger.error(f"No PDF output. stdout: {result.stdout}, stderr: {result.stderr}")
                raise ConversionError(
                    f"No PDF output from LibreOffice. "
                    f"stdout: {result.stdout}, stderr: {result.stderr}"
                )

            output_path = str(pdf_files[0])

            # Get page count
            doc = fitz.open(output_path)
            page_count = doc.page_count
            doc.close()

            # Move to temp_dir with unique name
            final_path = os.path.join(self.temp_dir, f"{uuid.uuid4()}.pdf")
            os.rename(output_path, final_path)

            logger.info(
                f"Converted {original_filename} to PDF with {page_count} pages"
            )
            return final_path, page_count

        except subprocess.TimeoutExpired:
            logger.error(f"LibreOffice conversion timed out after 90s for {original_filename}")
            raise ConversionError(
                "LibreOffice conversion timed out (90s). "
                "The file may be too large or complex."
            )
        finally:
            # Cleanup output and profile directories
            shutil.rmtree(output_dir, ignore_errors=True)
            shutil.rmtree(user_profile_dir, ignore_errors=True)

    def _convert_image(self, input_path: str) -> Tuple[str, int]:
        """
        Convert image to PDF using Pillow and reportlab.
        Fits image to A4 while preserving aspect ratio.
        """
        try:
            # Open and convert image
            img = Image.open(input_path)

            # Convert to RGB if necessary (for RGBA, P, etc.)
            if img.mode in ("RGBA", "P", "LA"):
                background = Image.new("RGB", img.size, (255, 255, 255))
                if img.mode == "P":
                    img = img.convert("RGBA")
                background.paste(img, mask=img.split()[-1] if img.mode == "RGBA" else None)
                img = background
            elif img.mode != "RGB":
                img = img.convert("RGB")

            # Get image dimensions
            img_width, img_height = img.size
            img_ratio = img_width / img_height

            # Calculate page size based on image orientation
            if img_ratio > 1:  # Landscape
                page_width = A4_HEIGHT_PT
                page_height = A4_WIDTH_PT
            else:  # Portrait
                page_width = A4_WIDTH_PT
                page_height = A4_HEIGHT_PT

            # Calculate available space (with margins)
            margin_pt = MARGIN_MM * mm
            available_width = page_width - (2 * margin_pt)
            available_height = page_height - (2 * margin_pt)

            # Calculate scaled dimensions
            available_ratio = available_width / available_height
            if img_ratio > available_ratio:
                # Image is wider - fit to width
                draw_width = available_width
                draw_height = available_width / img_ratio
            else:
                # Image is taller - fit to height
                draw_height = available_height
                draw_width = available_height * img_ratio

            # Center on page
            x = margin_pt + (available_width - draw_width) / 2
            y = margin_pt + (available_height - draw_height) / 2

            # Create PDF
            output_path = os.path.join(self.temp_dir, f"{uuid.uuid4()}.pdf")

            c = canvas.Canvas(output_path, pagesize=(page_width, page_height))

            # Save image to temp file for reportlab
            temp_img_path = os.path.join(self.temp_dir, f"{uuid.uuid4()}_temp.jpg")
            img.save(temp_img_path, "JPEG", quality=95)

            # Draw image
            c.drawImage(
                temp_img_path,
                x, y,
                width=draw_width,
                height=draw_height,
            )
            c.save()

            # Cleanup temp image
            os.unlink(temp_img_path)

            logger.info(f"Converted image to PDF: {output_path}")
            return output_path, 1

        except Exception as e:
            raise ConversionError(f"Image conversion failed: {e}")

    def get_pdf_page_count(self, pdf_path: str) -> int:
        """Get the number of pages in a PDF."""
        doc = fitz.open(pdf_path)
        count = doc.page_count
        doc.close()
        return count


# Singleton instance
_pdf_converter: Optional[PDFConverter] = None


def get_pdf_converter() -> PDFConverter:
    """Get the PDF converter singleton."""
    global _pdf_converter
    if _pdf_converter is None:
        _pdf_converter = PDFConverter()
    return _pdf_converter
