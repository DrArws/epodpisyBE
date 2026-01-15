"""
PDF signing module using PyMuPDF (fitz) and PAdES (via Java KMS signer).
Overlays signature image on specified page and coordinates.
Adds verification stamp with signing details and QR code.
Optionally creates PAdES-BASELINE-T digital signatures using Cloud KMS.
"""
import io
import logging
import os
import uuid
import base64
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import StampConfig

import fitz  # PyMuPDF
import qrcode
from PIL import Image

from app.pdf.pades import (
    PAdESSigner,
    PAdESAuditRecord,
    PAdESSigningError,
    get_pades_signer,
    is_pades_available,
)

logger = logging.getLogger(__name__)

# Font paths for Czech diacritics support
# These fonts are installed in Dockerfile: fonts-dejavu-core, fonts-freefont-ttf
FONT_PATHS = {
    "regular": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ],
    "bold": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ],
}


def _find_font(style: str = "regular") -> Optional[str]:
    """Find a font file with Czech diacritics support."""
    for path in FONT_PATHS.get(style, FONT_PATHS["regular"]):
        if os.path.exists(path):
            return path
    return None


@dataclass
class SignaturePlacement:
    """
    Signature placement coordinates with normalization support.

    PDF coordinate system: origin at bottom-left, Y increases upward.
    All coordinates in points (1 point = 1/72 inch).

    Supports conversion from different coordinate systems:
    - origin: "bottom-left" (PDF default), "top-left" (browser/image)
    - unit: "pt" (points), "px" (pixels at 72 DPI), "mm", "in"
    - rotation: 0, 90, 180, 270 degrees (page rotation)
    """
    page: int  # 1-indexed page number
    x: float   # X from left in points
    y: float   # Y from bottom in points
    w: float   # Width in points
    h: float   # Height in points
    origin: str = "bottom-left"  # Coordinate origin
    unit: str = "pt"  # Unit of measurement
    rotation: int = 0  # Page rotation in degrees

    @classmethod
    def from_normalized(
        cls,
        page: int,
        x: float,
        y: float,
        w: float,
        h: float,
        page_height: float,  # Page height in points for Y flip
        origin: str = "bottom-left",
        unit: str = "pt",
        rotation: int = 0,
    ) -> "SignaturePlacement":
        """
        Create placement from coordinates in any system, normalized to PDF coordinates.

        Args:
            page: 1-indexed page number
            x, y, w, h: Coordinates in specified unit
            page_height: Page height in points (needed for top-left origin)
            origin: "bottom-left" (PDF) or "top-left" (browser)
            unit: "pt", "px" (at 72 DPI), "mm", or "in"
            rotation: Page rotation 0, 90, 180, 270
        """
        # Unit conversion factors to points
        unit_to_pt = {
            "pt": 1.0,
            "px": 1.0,  # Assume 72 DPI (1px = 1pt)
            "mm": 72.0 / 25.4,  # 25.4mm per inch
            "in": 72.0,
        }
        factor = unit_to_pt.get(unit, 1.0)

        # Convert to points
        x_pt = x * factor
        y_pt = y * factor
        w_pt = w * factor
        h_pt = h * factor

        # Handle origin conversion (top-left to bottom-left)
        if origin == "top-left":
            # Flip Y: PDF origin is bottom-left, browser origin is top-left
            y_pt = page_height - y_pt - h_pt

        # TODO: Handle page rotation if needed
        # For now, rotation is stored for audit but not applied

        return cls(
            page=page,
            x=x_pt,
            y=y_pt,
            w=w_pt,
            h=h_pt,
            origin="bottom-left",  # Normalized to PDF
            unit="pt",
            rotation=rotation,
        )

    def to_dict(self) -> dict:
        """Export placement with full metadata for audit."""
        return {
            "page": self.page,
            "x": self.x,
            "y": self.y,
            "w": self.w,
            "h": self.h,
            "origin": self.origin,
            "unit": self.unit,
            "rotation": self.rotation,
        }


@dataclass
class StampInfo:
    """
    Information for the verification stamp.

    Note: Hash is NOT included in stamp because the hash can only be computed
    AFTER the stamp is added. Hash is stored in database and evidence report.
    """
    verification_id: str  # Short public ID for verification (e.g., "VRF-ABC123")
    verify_url: str  # Full verification URL (e.g., "https://drbacon.cz/verify/VRF-ABC123")
    signer_name: str
    signed_at: datetime
    document_id: str
    verification_method: Optional[str] = None  # "sms" or "whatsapp"
    phone_masked: Optional[str] = None  # e.g., "+420***789"
    include_qr: bool = True
    # Stamp configuration from workspace settings
    config: Optional["StampConfig"] = None


class SigningError(Exception):
    """PDF signing error."""
    pass


class PlacementValidationError(SigningError):
    """Invalid signature placement error."""

    def __init__(self, message: str, code: str = "INVALID_PLACEMENT"):
        super().__init__(message)
        self.code = code
        self.message = message


# Tolerance for bounds checking (in points, ~1mm)
PLACEMENT_BOUNDS_TOLERANCE = 3.0


def validate_placement(
    placement: SignaturePlacement,
    page_count: int,
    page_width: float,
    page_height: float,
) -> None:
    """
    Validate signature placement against document constraints.

    Args:
        placement: Signature placement coordinates
        page_count: Total number of pages in document
        page_width: Width of target page in points
        page_height: Height of target page in points

    Raises:
        PlacementValidationError: If placement is invalid
    """
    # Validate page number (1-indexed)
    if not isinstance(placement.page, int) or placement.page < 1:
        raise PlacementValidationError(
            f"Neplatné číslo stránky: {placement.page}. Musí být celé číslo >= 1.",
            code="INVALID_PAGE_NUMBER"
        )

    if placement.page > page_count:
        raise PlacementValidationError(
            f"Stránka {placement.page} neexistuje. Dokument má {page_count} stránek.",
            code="PAGE_OUT_OF_RANGE"
        )

    # Validate dimensions (w, h must be positive)
    if placement.w <= 0:
        raise PlacementValidationError(
            f"Šířka podpisu musí být kladná, zadáno: {placement.w}",
            code="INVALID_WIDTH"
        )

    if placement.h <= 0:
        raise PlacementValidationError(
            f"Výška podpisu musí být kladná, zadáno: {placement.h}",
            code="INVALID_HEIGHT"
        )

    # Validate position (x, y must be non-negative)
    if placement.x < 0:
        raise PlacementValidationError(
            f"Pozice X nesmí být záporná, zadáno: {placement.x}",
            code="INVALID_X_POSITION"
        )

    if placement.y < 0:
        raise PlacementValidationError(
            f"Pozice Y nesmí být záporná, zadáno: {placement.y}",
            code="INVALID_Y_POSITION"
        )

    # Validate bounds (signature must fit within page with tolerance)
    if placement.x + placement.w > page_width + PLACEMENT_BOUNDS_TOLERANCE:
        raise PlacementValidationError(
            f"Podpis přesahuje pravý okraj stránky. "
            f"X({placement.x}) + šířka({placement.w}) = {placement.x + placement.w}, "
            f"ale šířka stránky je {page_width}.",
            code="EXCEEDS_PAGE_WIDTH"
        )

    if placement.y + placement.h > page_height + PLACEMENT_BOUNDS_TOLERANCE:
        raise PlacementValidationError(
            f"Podpis přesahuje horní okraj stránky. "
            f"Y({placement.y}) + výška({placement.h}) = {placement.y + placement.h}, "
            f"ale výška stránky je {page_height}.",
            code="EXCEEDS_PAGE_HEIGHT"
        )


class PDFSigner:
    """PDF signature overlay using PyMuPDF."""

    def __init__(self, temp_dir: str = "/tmp"):
        self.temp_dir = temp_dir

    def sign_pdf(
        self,
        pdf_path: str,
        signature_png_base64: str,
        placement: SignaturePlacement,
        signer_name: str,
        stamp_info: Optional[StampInfo] = None,
    ) -> str:
        """
        Add signature image overlay and verification stamp to PDF.

        Args:
            pdf_path: Path to input PDF
            signature_png_base64: Base64-encoded PNG signature image
            placement: Signature placement coordinates
            signer_name: Name of signer (for metadata)
            stamp_info: Optional stamp information for verification seal

        Returns:
            Path to signed PDF

        Raises:
            SigningError: If signing fails
        """
        try:
            # Decode signature image
            signature_data = self._decode_signature(signature_png_base64)

            # Open PDF
            doc = fitz.open(pdf_path)

            # Get target page (0-indexed internally) for dimension check
            # First validate page exists
            if placement.page < 1 or placement.page > doc.page_count:
                raise PlacementValidationError(
                    f"Stránka {placement.page} neexistuje. Dokument má {doc.page_count} stránek.",
                    code="PAGE_OUT_OF_RANGE"
                )

            page = doc[placement.page - 1]

            # PDF coordinates: (0,0) is bottom-left
            # PyMuPDF rect uses (x0, y0, x1, y1) where (0,0) is top-left
            # We need to convert from bottom-left to top-left coordinate system
            page_height = page.rect.height
            page_width = page.rect.width

            # Comprehensive placement validation
            validate_placement(
                placement=placement,
                page_count=doc.page_count,
                page_width=page_width,
                page_height=page_height,
            )

            # Convert Y coordinate (flip from bottom-left to top-left)
            y_top = page_height - placement.y - placement.h

            # Create rectangle for signature placement
            sig_rect = fitz.Rect(
                placement.x,           # x0 (left)
                y_top,                 # y0 (top in PyMuPDF coords)
                placement.x + placement.w,  # x1 (right)
                y_top + placement.h,   # y1 (bottom in PyMuPDF coords)
            )

            # Insert signature image
            page.insert_image(
                sig_rect,
                stream=signature_data,
                keep_proportion=True,
            )

            # Add verification stamp below signature
            if stamp_info:
                self._add_verification_stamp(
                    page=page,
                    stamp_info=stamp_info,
                    signature_rect=sig_rect,
                    page_height=page_height,
                    page_width=page_width,
                )

            # Add metadata to PDF
            metadata = doc.metadata or {}
            metadata["keywords"] = (
                f"{metadata.get('keywords', '')} "
                f"Signed by: {signer_name} | "
                f"Verification: {stamp_info.verification_id if stamp_info else 'N/A'}"
            ).strip()
            metadata["producer"] = "E-Signing Service (drbacon.cz)"
            doc.set_metadata(metadata)

            # Save to new file
            output_path = os.path.join(
                self.temp_dir,
                f"{uuid.uuid4()}_signed.pdf"
            )

            doc.save(output_path, garbage=4, deflate=True)
            doc.close()

            logger.info(
                f"Added signature to page {placement.page} at "
                f"({placement.x}, {placement.y}) size ({placement.w}x{placement.h})"
            )

            return output_path

        except fitz.FileDataError as e:
            raise SigningError(f"Invalid PDF file: {e}")
        except Exception as e:
            logger.exception("Failed to sign PDF")
            raise SigningError(f"Failed to sign PDF: {e}")

    def sign_pdf_pades(
        self,
        pdf_path: str,
        signature_png_base64: str,
        placement: SignaturePlacement,
        signer_name: str,
        stamp_info: Optional[StampInfo] = None,
        use_visual_overlay: bool = True,
    ) -> Tuple[str, Optional[PAdESAuditRecord]]:
        """
        Create PAdES digital signature on PDF with clickable visible signature.

        NEW FLOW (clickable signature in Acrobat):
        1. Add verification stamp (doložka) to PDF (if stamp_info provided)
        2. Save signature PNG to temp file
        3. Java module creates signature field with PNG as appearance and signs

        The signature image becomes the appearance stream (AP) of the signature widget,
        making it clickable in Adobe Acrobat to show signature details.

        Args:
            pdf_path: Path to input PDF
            signature_png_base64: Base64-encoded PNG signature image
            placement: Signature placement coordinates
            signer_name: Name of signer
            stamp_info: Optional stamp information for verification seal
            use_visual_overlay: If True, adds visible signature (always True for visible sig)

        Returns:
            Tuple of (signed_pdf_path, pades_audit_record)

        Raises:
            SigningError: If signing fails
        """
        import tempfile

        temp_files = []

        try:
            logger.info(f"Starting PAdES signing for: {signer_name}")
            logger.info(f"Placement: page={placement.page}, x={placement.x}, y={placement.y}, "
                       f"w={placement.w}, h={placement.h}")

            # Step 1: Add verification stamp BEFORE cryptographic signing
            # The stamp is a separate annotation, not part of the signature field
            intermediate_path = pdf_path
            if stamp_info and use_visual_overlay:
                logger.info("Adding verification stamp (doložka) before signing...")
                intermediate_path = self._add_stamp_only(
                    pdf_path=pdf_path,
                    placement=placement,
                    stamp_info=stamp_info,
                )
                temp_files.append(intermediate_path)

            # Step 2: Save signature PNG to temp file
            signature_image_path = None
            if signature_png_base64 and use_visual_overlay:
                logger.info("Saving signature image for visible signature field...")
                signature_data = self._decode_signature(signature_png_base64)
                fd, signature_image_path = tempfile.mkstemp(suffix=".png", prefix="sig_")
                os.close(fd)
                with open(signature_image_path, "wb") as f:
                    f.write(signature_data)
                temp_files.append(signature_image_path)
                logger.info(f"Signature image saved: {signature_image_path}")

            # Step 3: Apply PAdES cryptographic signature with visible appearance
            logger.info("Applying PAdES cryptographic signature with visible appearance...")
            pades_signer = get_pades_signer()

            # Convert placement to dict for Java module
            # Note: Java expects Y from BOTTOM (PDF standard), our placement.y is also from bottom
            placement_dict = {
                "page": placement.page,
                "x": placement.x,
                "y": placement.y,
                "w": placement.w,
                "h": placement.h,
            }

            signed_path, audit = pades_signer.sign_pdf(
                pdf_path=intermediate_path,
                signer_name=signer_name,
                signature_image_path=signature_image_path,
                placement=placement_dict if signature_image_path else None,
            )

            logger.info(f"PAdES signing completed: {signed_path}")
            logger.info(f"Signature profile: {audit.signature_profile if audit else 'unknown'}")
            if signature_image_path:
                logger.info("Visible signature field created - clickable in Acrobat")

            return signed_path, audit

        except PAdESSigningError as e:
            logger.error(f"PAdES signing failed: {e}")
            raise SigningError(f"PAdES signing failed: {e}")
        except Exception as e:
            logger.exception("Failed to create PAdES signature")
            raise SigningError(f"Failed to create PAdES signature: {e}")
        finally:
            # Cleanup temp files
            for temp_file in temp_files:
                try:
                    if temp_file and os.path.exists(temp_file):
                        os.remove(temp_file)
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp file {temp_file}: {e}")

    def _add_stamp_only(
        self,
        pdf_path: str,
        placement: SignaturePlacement,
        stamp_info: StampInfo,
    ) -> str:
        """
        Add verification stamp (doložka) to PDF without adding signature image.

        This is called BEFORE the Java module adds the cryptographic signature,
        so the stamp becomes part of the signed content.

        Args:
            pdf_path: Path to input PDF
            placement: Signature placement (for relative stamp positioning)
            stamp_info: Stamp information

        Returns:
            Path to PDF with stamp added
        """
        import tempfile

        try:
            doc = fitz.open(pdf_path)
            page_index = placement.page - 1
            page = doc[page_index]
            page_rect = page.rect
            page_height = page_rect.height
            page_width = page_rect.width

            # Create a signature rect for stamp positioning reference
            sig_rect = fitz.Rect(
                placement.x,
                page_height - placement.y - placement.h,  # Convert to top-left origin
                placement.x + placement.w,
                page_height - placement.y,
            )

            # Add the verification stamp
            self._add_verification_stamp(
                page=page,
                stamp_info=stamp_info,
                signature_rect=sig_rect,
                page_height=page_height,
                page_width=page_width,
            )

            # Save to temp file
            fd, output_path = tempfile.mkstemp(suffix=".pdf", prefix="stamped_")
            os.close(fd)
            doc.save(output_path)
            doc.close()

            logger.info(f"Verification stamp added: {output_path}")
            return output_path

        except Exception as e:
            logger.exception("Failed to add verification stamp")
            raise SigningError(f"Failed to add verification stamp: {e}")

    def _add_verification_stamp(
        self,
        page: fitz.Page,
        stamp_info: StampInfo,
        signature_rect: fitz.Rect,
        page_height: float,
        page_width: float,
    ) -> None:
        """
        Add verification stamp with QR code.
        Position and style are controlled by stamp_info.config (StampConfig).

        Args:
            page: PyMuPDF page object
            stamp_info: Stamp information including config
            signature_rect: Rectangle of the signature (for relative positioning)
            page_height: Page height in points
            page_width: Page width in points
        """
        # Import StampConfig here to avoid circular imports
        from app.models import StampConfig, StampPosition

        # Get config or use defaults
        config = stamp_info.config or StampConfig()

        # Stamp dimensions from config
        stamp_width = config.width
        stamp_height = config.height
        qr_size = config.qr_size if config.include_qr else 0
        padding = 6

        # Calculate stamp position based on config.position
        stamp_x, stamp_y = self._calculate_stamp_position(
            config=config,
            signature_rect=signature_rect,
            stamp_width=stamp_width,
            stamp_height=stamp_height,
            page_width=page_width,
            page_height=page_height,
        )

        stamp_rect = fitz.Rect(
            stamp_x,
            stamp_y,
            stamp_x + stamp_width,
            stamp_y + stamp_height,
        )

        # Colors from config (convert hex to RGB tuples)
        border_color = config.hex_to_rgb(config.border_color)
        bg_color = config.hex_to_rgb(config.bg_color)
        header_color = config.hex_to_rgb(config.header_color)
        text_color = config.hex_to_rgb(config.text_color)
        light_gray = (0.5, 0.5, 0.5)
        warning_color = (0.6, 0.3, 0.3)  # Reddish

        # Draw background rectangle with border
        shape = page.new_shape()
        shape.draw_rect(stamp_rect)
        shape.finish(
            color=border_color,
            fill=bg_color,
            width=1.5,
        )
        shape.commit()

        # Calculate text area (leave space for QR on the right)
        text_width = stamp_width - qr_size - padding * 3 if config.include_qr else stamp_width - padding * 2
        text_x = stamp_x + padding

        # Prepare text content based on config visibility settings
        lines = []

        # Line 1: Header (always shown)
        lines.append({
            "text": config.header_text,
            "size": 7,
            "color": header_color,
            "bold": True,
        })

        # Line 2: Signer name
        if config.show_signer_name:
            lines.append({
                "text": stamp_info.signer_name,
                "size": 8,
                "color": text_color,
                "bold": True,
            })

        # Line 3: Date/time
        if config.show_date:
            if isinstance(stamp_info.signed_at, str):
                dt_str = stamp_info.signed_at
            else:
                dt_str = stamp_info.signed_at.strftime("%d.%m.%Y %H:%M:%S UTC")
            lines.append({
                "text": dt_str,
                "size": 7,
                "color": text_color,
                "bold": False,
            })

        # Line 4: Verification method
        if config.show_verification_method and stamp_info.verification_method:
            method = "SMS OTP" if stamp_info.verification_method == "sms" else "WhatsApp OTP"
            phone = f" ({stamp_info.phone_masked})" if stamp_info.phone_masked else ""
            lines.append({
                "text": f"Overeno: {method}{phone}",
                "size": 6,
                "color": light_gray,
                "bold": False,
            })

        # Line 5: Verification ID
        if config.show_verification_id:
            lines.append({
                "text": f"ID: {stamp_info.verification_id}",
                "size": 6,
                "color": light_gray,
                "bold": False,
            })

        # Line 6: Warning
        if config.show_warning:
            lines.append({
                "text": config.warning_text,
                "size": 5,
                "color": warning_color,
                "bold": False,
            })

        # Find fonts with Czech diacritics support
        font_regular = _find_font("regular")
        font_bold = _find_font("bold")

        # Draw text lines
        y_offset = stamp_y + padding + 2
        for line in lines:
            text = line["text"]

            # Try to use system font with diacritics
            font_path = font_bold if line["bold"] else font_regular

            if font_path:
                try:
                    page.insert_text(
                        (text_x, y_offset + line["size"]),
                        text,
                        fontfile=font_path,
                        fontsize=line["size"],
                        color=line["color"],
                    )
                    y_offset += line["size"] + 3
                    continue
                except Exception as e:
                    logger.warning(f"Font {font_path} failed: {e}")

            # Fallback to built-in font with transliteration
            fontname = "hebo" if line["bold"] else "helv"
            ascii_text = self._transliterate_czech(text)
            try:
                page.insert_text(
                    (text_x, y_offset + line["size"]),
                    ascii_text,
                    fontname=fontname,
                    fontsize=line["size"],
                    color=line["color"],
                )
            except Exception as e:
                logger.warning(f"Text insertion failed: {e}")

            y_offset += line["size"] + 3

        # Add QR code
        if config.include_qr:
            qr_rect = fitz.Rect(
                stamp_x + stamp_width - qr_size - padding,
                stamp_y + padding,
                stamp_x + stamp_width - padding,
                stamp_y + padding + qr_size,
            )

            try:
                qr_bytes = self._generate_qr_code(stamp_info.verify_url, int(qr_size))
                page.insert_image(qr_rect, stream=qr_bytes)
            except Exception as e:
                logger.warning(f"Failed to generate QR code: {e}")

        logger.info(f"Added verification stamp: {stamp_info.verification_id} at ({stamp_x:.0f}, {stamp_y:.0f})")

    def _calculate_stamp_position(
        self,
        config: "StampConfig",
        signature_rect: fitz.Rect,
        stamp_width: float,
        stamp_height: float,
        page_width: float,
        page_height: float,
    ) -> Tuple[float, float]:
        """
        Calculate stamp position based on config.

        Returns:
            Tuple of (x, y) coordinates for stamp placement.
        """
        from app.models import StampPosition

        margin = 20  # Page margin

        if config.position == StampPosition.FIXED:
            # Fixed position from config
            stamp_x = config.x if config.x is not None else margin
            stamp_y = config.y if config.y is not None else margin
            return stamp_x, stamp_y

        elif config.position == StampPosition.BOTTOM_RIGHT:
            stamp_x = page_width - stamp_width - margin
            stamp_y = page_height - stamp_height - margin
            return stamp_x, stamp_y

        elif config.position == StampPosition.BOTTOM_LEFT:
            stamp_x = margin
            stamp_y = page_height - stamp_height - margin
            return stamp_x, stamp_y

        elif config.position == StampPosition.ABOVE_SIGNATURE:
            stamp_x = signature_rect.x0 + config.offset_x
            stamp_y = signature_rect.y0 - stamp_height - config.offset_y
            # Ensure stamp stays on page
            if stamp_y < margin:
                stamp_y = margin
            return stamp_x, stamp_y

        elif config.position == StampPosition.LEFT_OF_SIGNATURE:
            stamp_x = signature_rect.x0 - stamp_width - config.offset_x
            stamp_y = signature_rect.y0 + config.offset_y
            # Ensure stamp stays on page
            if stamp_x < margin:
                stamp_x = margin
            return stamp_x, stamp_y

        elif config.position == StampPosition.RIGHT_OF_SIGNATURE:
            stamp_x = signature_rect.x1 + config.offset_x
            stamp_y = signature_rect.y0 + config.offset_y
            # Ensure stamp stays on page
            if stamp_x + stamp_width > page_width - margin:
                stamp_x = page_width - stamp_width - margin
            return stamp_x, stamp_y

        else:  # BELOW_SIGNATURE (default)
            stamp_x = signature_rect.x0 + config.offset_x
            stamp_y = signature_rect.y1 + config.offset_y

            # Check if stamp fits on page, if not try above signature
            if stamp_y + stamp_height > page_height - margin:
                stamp_y = signature_rect.y0 - stamp_height - config.offset_y

            # If still doesn't fit, place at bottom right of page
            if stamp_y < margin:
                stamp_x = page_width - stamp_width - margin
                stamp_y = page_height - stamp_height - margin

            return stamp_x, stamp_y

    def _generate_qr_code(self, url: str, size: int) -> bytes:
        """
        Generate QR code as PNG bytes.

        Args:
            url: URL to encode
            size: Size in points (approximate)

        Returns:
            PNG image bytes
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=4,
            border=1,
        )
        qr.add_data(url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Resize to target size
        img = img.resize((size * 2, size * 2), Image.Resampling.LANCZOS)

        # Convert to bytes
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    def _transliterate_czech(self, text: str) -> str:
        """Transliterate Czech characters to ASCII."""
        replacements = {
            'á': 'a', 'č': 'c', 'ď': 'd', 'é': 'e', 'ě': 'e',
            'í': 'i', 'ň': 'n', 'ó': 'o', 'ř': 'r', 'š': 's',
            'ť': 't', 'ú': 'u', 'ů': 'u', 'ý': 'y', 'ž': 'z',
            'Á': 'A', 'Č': 'C', 'Ď': 'D', 'É': 'E', 'Ě': 'E',
            'Í': 'I', 'Ň': 'N', 'Ó': 'O', 'Ř': 'R', 'Š': 'S',
            'Ť': 'T', 'Ú': 'U', 'Ů': 'U', 'Ý': 'Y', 'Ž': 'Z',
        }
        for cz, ascii_char in replacements.items():
            text = text.replace(cz, ascii_char)
        return text

    def _decode_signature(self, signature_base64: str) -> bytes:
        """
        Decode base64 signature image.

        Args:
            signature_base64: Base64 string (optionally with data URL prefix)

        Returns:
            PNG image bytes

        Raises:
            SigningError: If decoding fails
        """
        try:
            # Remove data URL prefix if present
            if signature_base64.startswith("data:image/png;base64,"):
                signature_base64 = signature_base64[22:]

            data = base64.b64decode(signature_base64)

            # Validate PNG magic bytes
            if not data[:8] == b'\x89PNG\r\n\x1a\n':
                raise SigningError("Invalid PNG signature")

            return data

        except Exception as e:
            raise SigningError(f"Failed to decode signature: {e}")

    def get_page_dimensions(self, pdf_path: str, page_num: int = 1) -> dict:
        """
        Get dimensions of a PDF page.

        Args:
            pdf_path: Path to PDF
            page_num: 1-indexed page number

        Returns:
            Dict with width, height in points
        """
        doc = fitz.open(pdf_path)
        page = doc[page_num - 1]
        dimensions = {
            "width": page.rect.width,
            "height": page.rect.height,
        }
        doc.close()
        return dimensions

    def add_multiple_signatures(
        self,
        pdf_path: str,
        signatures: list,
    ) -> str:
        """
        Add multiple signatures to a PDF.

        Args:
            pdf_path: Path to input PDF
            signatures: List of dicts with:
                - signature_png_base64: str
                - placement: SignaturePlacement
                - signer_name: str
                - stamp_info: Optional[StampInfo]

        Returns:
            Path to signed PDF
        """
        current_path = pdf_path

        for sig in signatures:
            current_path = self.sign_pdf(
                pdf_path=current_path,
                signature_png_base64=sig["signature_png_base64"],
                placement=sig["placement"],
                signer_name=sig["signer_name"],
                stamp_info=sig.get("stamp_info"),
            )

        return current_path


def generate_verification_id() -> str:
    """
    Generate a short, human-readable verification ID.
    Format: VRF-XXXXXX (6 alphanumeric chars)
    """
    import secrets
    import string
    chars = string.ascii_uppercase + string.digits
    # Remove confusing characters
    chars = chars.replace('O', '').replace('0', '').replace('I', '').replace('1', '').replace('L', '')
    random_part = ''.join(secrets.choice(chars) for _ in range(6))
    return f"VRF-{random_part}"


# Singleton instance
_pdf_signer: Optional[PDFSigner] = None


def get_pdf_signer() -> PDFSigner:
    """Get the PDF signer singleton."""
    global _pdf_signer
    if _pdf_signer is None:
        _pdf_signer = PDFSigner()
    return _pdf_signer


# Re-export PAdES utilities for convenience
__all__ = [
    "PDFSigner",
    "SignaturePlacement",
    "StampInfo",
    "SigningError",
    "PlacementValidationError",
    "validate_placement",
    "get_pdf_signer",
    "generate_verification_id",
    "is_pades_available",
    "PAdESAuditRecord",
    "PAdESSigningError",
]
