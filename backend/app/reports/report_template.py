from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# SecureChain Professional Color Palette
COLOR_PRIMARY = colors.HexColor("#0F172A")    # Slate 900
COLOR_SECONDARY = colors.HexColor("#1E293B")  # Slate 800
COLOR_ACCENT = colors.HexColor("#2563EB")     # Blue 600
COLOR_MUTED = colors.HexColor("#64748B")      # Slate 500
COLOR_LIGHT_BG = colors.HexColor("#F8FAFC")   # Slate 50

# Severity Colors
COLOR_CRITICAL = colors.HexColor("#DC2626")   # Red 600
COLOR_HIGH = colors.HexColor("#EA580C")       # Orange 600
COLOR_MEDIUM = colors.HexColor("#D97706")     # Amber 600
COLOR_LOW = colors.HexColor("#2563EB")        # Blue 600
COLOR_INFO = colors.HexColor("#475569")       # Slate 600
COLOR_SECURE = colors.HexColor("#16A34A")     # Emerald 600

def get_report_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=COLOR_PRIMARY,
        alignment=TA_LEFT,
        spaceAfter=10
    ))

    styles.add(ParagraphStyle(
        name="ReportSubtitle",
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=COLOR_MUTED,
        alignment=TA_LEFT,
        spaceAfter=20
    ))

    styles.add(ParagraphStyle(
        name="SectionHeading",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=COLOR_PRIMARY,
        spaceBefore=15,
        spaceAfter=8,
        keepWithNext=True
    ))

    styles.add(ParagraphStyle(
        name="FindingTitle",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=COLOR_PRIMARY,
        spaceAfter=4
    ))

    styles.add(ParagraphStyle(
        name="CodeBlock",
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A"),
        backColor=colors.HexColor("#F1F5F9"),
        spaceBefore=4,
        spaceAfter=6,
        borderPadding=6
    ))

    styles.add(ParagraphStyle(
        name="MetaText",
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=COLOR_MUTED
    ))

    return styles
