from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors

def create_severity_distribution_bar(counts: dict, width: int = 480, height: int = 24) -> Drawing:
    """Generates a compact horizontal stacked bar showing severity proportions."""
    d = Drawing(width, height)
    total = sum(counts.values())
    if total == 0:
        d.add(Rect(0, 0, width, height, fillColor=colors.HexColor("#16A34A"), strokeColor=None))
        d.add(String(width / 2 - 40, 7, "100% SECURE - NO FINDINGS", fontSize=9, fontName="Helvetica-Bold", fillColor=colors.white))
        return d

    color_map = {
        "CRITICAL": colors.HexColor("#DC2626"),
        "HIGH": colors.HexColor("#EA580C"),
        "MEDIUM": colors.HexColor("#D97706"),
        "LOW": colors.HexColor("#2563EB"),
        "INFORMATIONAL": colors.HexColor("#475569")
    }

    current_x = 0
    for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        cnt = counts.get(key, 0)
        if cnt > 0:
            bar_w = (cnt / total) * width
            d.add(Rect(current_x, 0, bar_w, height, fillColor=color_map[key], strokeColor=colors.white, strokeWidth=1))
            if bar_w > 20:
                d.add(String(current_x + 5, 7, f"{cnt}", fontSize=8, fontName="Helvetica-Bold", fillColor=colors.white))
            current_x += bar_w

    return d
