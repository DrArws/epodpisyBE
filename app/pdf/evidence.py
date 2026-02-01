"""
Evidence report generator.
Creates a PDF audit trail document with signing details.
"""
import logging
import os
import uuid
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

logger = logging.getLogger(__name__)

# Register fonts with Czech diacritics support
# These fonts are installed in Dockerfile
_FONTS_REGISTERED = False

FONT_PATHS = {
    "DejaVuSans": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "DejaVuSans-Bold": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "FreeSans": "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    "FreeSansBold": "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    "LiberationSans": "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "LiberationSans-Bold": "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
}

# Font names to use (will be set after registration)
FONT_NORMAL = "Helvetica"  # Fallback
FONT_BOLD = "Helvetica-Bold"  # Fallback
FONT_MONO = "Courier"  # Fallback


def _register_fonts():
    """Register TTF fonts for Czech diacritics support."""
    global _FONTS_REGISTERED, FONT_NORMAL, FONT_BOLD, FONT_MONO

    if _FONTS_REGISTERED:
        return

    # Try to register DejaVu fonts (best Czech support)
    try:
        if os.path.exists(FONT_PATHS["DejaVuSans"]):
            pdfmetrics.registerFont(TTFont("DejaVuSans", FONT_PATHS["DejaVuSans"]))
            FONT_NORMAL = "DejaVuSans"
            logger.info("Registered DejaVuSans font")

        if os.path.exists(FONT_PATHS["DejaVuSans-Bold"]):
            pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", FONT_PATHS["DejaVuSans-Bold"]))
            FONT_BOLD = "DejaVuSans-Bold"
            logger.info("Registered DejaVuSans-Bold font")

    except Exception as e:
        logger.warning(f"Failed to register DejaVu fonts: {e}")

        # Try FreeSans as fallback
        try:
            if os.path.exists(FONT_PATHS["FreeSans"]):
                pdfmetrics.registerFont(TTFont("FreeSans", FONT_PATHS["FreeSans"]))
                FONT_NORMAL = "FreeSans"

            if os.path.exists(FONT_PATHS["FreeSansBold"]):
                pdfmetrics.registerFont(TTFont("FreeSansBold", FONT_PATHS["FreeSansBold"]))
                FONT_BOLD = "FreeSansBold"

        except Exception as e2:
            logger.warning(f"Failed to register FreeSans fonts: {e2}")
            # Keep Helvetica fallback (no diacritics)

    _FONTS_REGISTERED = True


# Register fonts on module load
_register_fonts()


@dataclass
class SignerInfo:
    """Signer information for evidence report."""
    name: str
    email: Optional[str]
    phone: Optional[str]
    otp_channel: Optional[str]
    viewed_at: Optional[datetime]
    otp_verified_at: Optional[datetime]
    signed_at: Optional[datetime]
    ip_address: Optional[str]
    user_agent: Optional[str]
    signature_placement: Optional[Dict] = None
    # NIA identity verification fields
    identity_method: Optional[str] = None  # "otp" or "nia"
    identity_verified_at: Optional[datetime] = None
    nia_loa: Optional[str] = None
    nia_subject_masked: Optional[str] = None  # Masked SePP for report
    nia_authn_instant: Optional[datetime] = None


@dataclass
class EventInfo:
    """Event information for evidence report."""
    event_type: str
    created_at: datetime
    signer_name: Optional[str]
    ip_address: Optional[str]
    metadata: Optional[Dict]


@dataclass
class DocumentInfo:
    """Document information for evidence report."""
    id: str
    name: str
    created_at: datetime
    completed_at: datetime
    workspace_id: str
    final_pdf_hash: str
    page_count: int


class EvidenceReportGenerator:
    """Generates evidence report PDF for signed documents."""

    def __init__(self, temp_dir: str = "/tmp"):
        self.temp_dir = temp_dir
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Configure custom paragraph styles with Czech diacritics support."""
        # Update base styles to use registered fonts
        self.styles['Normal'].fontName = FONT_NORMAL
        self.styles['Title'].fontName = FONT_BOLD
        self.styles['Heading1'].fontName = FONT_BOLD
        self.styles['Heading2'].fontName = FONT_BOLD

        self.styles.add(ParagraphStyle(
            name='Title2',
            parent=self.styles['Title'],
            fontName=FONT_BOLD,
            fontSize=18,
            spaceAfter=12,
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontName=FONT_BOLD,
            fontSize=12,
            spaceBefore=12,
            spaceAfter=6,
            textColor=colors.HexColor('#1a1a1a'),
        ))
        self.styles.add(ParagraphStyle(
            name='BodySmall',
            parent=self.styles['Normal'],
            fontName=FONT_NORMAL,
            fontSize=9,
            leading=12,
        ))
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontName=FONT_NORMAL,
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER,
        ))

    def generate(
        self,
        document: DocumentInfo,
        signers: List[SignerInfo],
        events: List[EventInfo],
    ) -> str:
        """
        Generate evidence report PDF.

        Args:
            document: Document information
            signers: List of signer details
            events: List of events from audit trail

        Returns:
            Path to generated PDF
        """
        output_path = os.path.join(
            self.temp_dir,
            f"{uuid.uuid4()}_evidence.pdf"
        )

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=20*mm,
            leftMargin=20*mm,
            topMargin=20*mm,
            bottomMargin=20*mm,
        )

        elements = []

        # Title
        elements.append(Paragraph(
            "Kontrolní list elektronického podpisu",
            self.styles['Title2']
        ))
        elements.append(Paragraph(
            "Evidence Report / Audit Trail",
            self.styles['Normal']
        ))
        elements.append(Spacer(1, 10*mm))

        # Document Information
        elements.append(Paragraph("Informace o dokumentu", self.styles['SectionHeader']))
        elements.extend(self._build_document_section(document))
        elements.append(Spacer(1, 6*mm))

        # Signers Information
        elements.append(Paragraph("Podepisující osoby", self.styles['SectionHeader']))
        elements.extend(self._build_signers_section(signers))
        elements.append(Spacer(1, 6*mm))

        # Events Timeline
        elements.append(Paragraph("Časová osa událostí", self.styles['SectionHeader']))
        elements.extend(self._build_events_section(events))
        elements.append(Spacer(1, 6*mm))

        # Technical Details
        elements.append(Paragraph("Technické údaje", self.styles['SectionHeader']))
        elements.extend(self._build_technical_section(document, signers))

        # Footer
        elements.append(Spacer(1, 10*mm))
        elements.append(Paragraph(
            f"Vygenerováno: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            self.styles['Footer']
        ))
        elements.append(Paragraph(
            "Tento dokument je automaticky generovaný kontrolní list "
            "a slouží jako důkaz o průběhu elektronického podpisu.",
            self.styles['Footer']
        ))

        # Build PDF
        doc.build(elements)

        logger.info(f"Generated evidence report: {output_path}")
        return output_path

    def _build_document_section(self, document: DocumentInfo) -> list:
        """Build document information table."""
        data = [
            ["Název dokumentu:", document.name],
            ["ID dokumentu:", document.id],
            ["Workspace ID:", document.workspace_id],
            ["Vytvořeno:", self._format_datetime(document.created_at)],
            ["Dokončeno:", self._format_datetime(document.completed_at)],
            ["Počet stránek:", str(document.page_count)],
            ["SHA-256 hash:", document.final_pdf_hash[:32] + "..."],
        ]

        table = Table(data, colWidths=[50*mm, 120*mm])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), FONT_BOLD),
            ('FONTNAME', (1, 0), (1, -1), FONT_NORMAL),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))

        return [table]

    def _build_signers_section(self, signers: List[SignerInfo]) -> list:
        """Build signers information table."""
        elements = []

        for i, signer in enumerate(signers, 1):
            elements.append(Paragraph(
                f"Podepisující #{i}: {signer.name}",
                self.styles['BodySmall']
            ))

            # Determine verification method display
            method = signer.identity_method or "otp"
            method_label = "NIA (SAML2/eIDAS)" if method == "nia" else "OTP"

            data = [
                ["E-mail:", signer.email or "-"],
                ["Telefon:", self._mask_phone(signer.phone) if signer.phone else "-"],
                ["Metoda ověření:", method_label],
            ]

            if method == "nia":
                # NIA-specific fields
                data.append(["NIA ověřeno:", self._format_datetime(
                    signer.identity_verified_at or signer.otp_verified_at
                )])
                data.append(["NIA LoA:", signer.nia_loa or "-"])
                if signer.nia_subject_masked:
                    data.append(["NIA subjekt:", signer.nia_subject_masked])
                if signer.nia_authn_instant:
                    data.append(["NIA AuthnInstant:", self._format_datetime(signer.nia_authn_instant)])
            else:
                # OTP-specific fields
                data.append(["OTP kanál:", signer.otp_channel or "-"])
                data.append(["OTP ověřeno:", self._format_datetime(signer.otp_verified_at)])

            data.extend([
                ["Zobrazeno:", self._format_datetime(signer.viewed_at)],
                ["Podepsáno:", self._format_datetime(signer.signed_at)],
                ["IP adresa:", signer.ip_address or "-"],
            ])

            if signer.signature_placement:
                placement = signer.signature_placement
                data.append([
                    "Pozice podpisu:",
                    f"Strana {placement.get('page', '-')}, "
                    f"X={placement.get('x', 0):.1f}, "
                    f"Y={placement.get('y', 0):.1f}, "
                    f"Šířka={placement.get('w', 0):.1f}, "
                    f"Výška={placement.get('h', 0):.1f}"
                ])

            table = Table(data, colWidths=[40*mm, 130*mm])
            table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), FONT_BOLD),
                ('FONTNAME', (1, 0), (1, -1), FONT_NORMAL),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 4*mm))

        return elements

    def _build_events_section(self, events: List[EventInfo]) -> list:
        """Build events timeline table."""
        header = ["Čas", "Událost", "Osoba", "IP adresa"]
        data = [header]

        for event in events:
            data.append([
                self._format_datetime(event.created_at),
                self._translate_event_type(event.event_type),
                event.signer_name or "-",
                event.ip_address or "-",
            ])

        table = Table(data, colWidths=[40*mm, 50*mm, 40*mm, 40*mm])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTNAME', (0, 1), (-1, -1), FONT_NORMAL),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ]))

        return [table]

    def _build_technical_section(
        self,
        document: DocumentInfo,
        signers: List[SignerInfo],
    ) -> list:
        """Build technical details section."""
        # Collect unique user agents
        user_agents = list(set(
            s.user_agent for s in signers
            if s.user_agent
        ))

        data = [
            ["Plný SHA-256 hash:", ""],
            ["", document.final_pdf_hash],
        ]

        if user_agents:
            data.append(["User-Agent(s):", ""])
            for ua in user_agents[:3]:  # Limit to 3
                data.append(["", ua[:80] + "..." if len(ua) > 80 else ua])

        table = Table(data, colWidths=[40*mm, 130*mm])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), FONT_BOLD),
            ('FONTNAME', (1, 0), (1, -1), FONT_MONO),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))

        return [table]

    def _format_datetime(self, dt: Optional[datetime]) -> str:
        """Format datetime for display."""
        if dt is None:
            return "-"
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            except Exception:
                return dt
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    def _mask_phone(self, phone: str) -> str:
        """Mask phone number for privacy."""
        if len(phone) > 6:
            return phone[:3] + "***" + phone[-3:]
        return "***"

    def _translate_event_type(self, event_type: str) -> str:
        """Translate event type to Czech."""
        translations = {
            "DOCUMENT_CREATED": "Dokument vytvořen",
            "FILE_UPLOADED": "Soubor nahrán",
            "FILE_CONVERTED": "Převedeno do PDF",
            "SIGNING_LINK_SENT": "Odkaz odeslán",
            "DOCUMENT_VIEWED": "Dokument zobrazen",
            "OTP_SENT": "OTP odesláno",
            "OTP_OK": "OTP ověřeno",
            "OTP_FAIL": "OTP selhalo",
            "IDENTITY_VERIFIED": "Identita ověřena",
            "NIA_STARTED": "NIA ověření zahájeno",
            "SIGNED": "Podepsáno",
            "DECLINED": "Odmítnuto",
            "FINALIZED": "Dokončeno",
            "EVIDENCE_GENERATED": "Evidence vygenerována",
        }
        return translations.get(event_type, event_type)


# Singleton instance
_evidence_generator: Optional[EvidenceReportGenerator] = None


def get_evidence_generator() -> EvidenceReportGenerator:
    """Get the evidence report generator singleton."""
    global _evidence_generator
    if _evidence_generator is None:
        _evidence_generator = EvidenceReportGenerator()
    return _evidence_generator
