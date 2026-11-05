import os
from datetime import datetime, timezone
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib import colors
from app.config import settings
from app.reports.report_template import (
    get_report_styles, COLOR_PRIMARY, COLOR_SECONDARY, COLOR_ACCENT,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_INFO, COLOR_SECURE
)
from app.reports.charts import create_severity_distribution_bar

class PDFGenerator:
    @staticmethod
    def generate_report(
        scan_id: int,
        contract_data: Dict[str, Any],
        scan_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        fuzz_details: Dict[str, Any]
    ) -> str:
        """
        Builds a comprehensive PDF security audit report.
        Returns: absolute path to generated PDF report.
        """
        filename = f"SecureChain_Audit_Report_Scan_{scan_id}.pdf"
        output_path = os.path.join(settings.REPORTS_DIR, filename)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = get_report_styles()
        story = []

        # Header Title
        story.append(Paragraph("SECURECHAIN AUDITOR", styles["ReportTitle"]))
        story.append(Paragraph(
            "Intelligent Multi-Engine Smart Contract Vulnerability Detection & Risk Assessment Platform",
            styles["ReportSubtitle"]
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=COLOR_ACCENT, spaceAfter=15))

        # Contract & Audit Metadata Table
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        meta_table_data = [
            [
                Paragraph("<b>Target Contract:</b>", styles["MetaText"]),
                Paragraph(contract_data.get("name", "Unknown"), styles["MetaText"]),
                Paragraph("<b>Audit ID:</b>", styles["MetaText"]),
                Paragraph(f"SCA-{scan_id:06d}", styles["MetaText"]),
            ],
            [
                Paragraph("<b>Source File:</b>", styles["MetaText"]),
                Paragraph(contract_data.get("filename", "Contract.sol"), styles["MetaText"]),
                Paragraph("<b>Timestamp:</b>", styles["MetaText"]),
                Paragraph(now_str, styles["MetaText"]),
            ],
            [
                Paragraph("<b>Compiler Version:</b>", styles["MetaText"]),
                Paragraph(contract_data.get("compiler_version", "^0.8.0"), styles["MetaText"]),
                Paragraph("<b>Engines Deployed:</b>", styles["MetaText"]),
                Paragraph(", ".join(scan_data.get("engines_used", ["custom"])), styles["MetaText"]),
            ],
            [
                Paragraph("<b>On-Chain Address:</b>", styles["MetaText"]),
                Paragraph(contract_data.get("address") or "N/A (Local Source)", styles["MetaText"]),
                Paragraph("<b>Network:</b>", styles["MetaText"]),
                Paragraph(contract_data.get("network", "ethereum"), styles["MetaText"]),
            ]
        ]

        meta_table = Table(meta_table_data, colWidths=[100, 160, 100, 160])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 15))

        # Executive Summary & Risk Gauge Table
        story.append(Paragraph("Executive Risk Assessment", styles["SectionHeading"]))
        
        risk_level = scan_data.get("risk_level", "SECURE")
        risk_score = scan_data.get("risk_score", 0.0)

        badge_color = {
            "CRITICAL": COLOR_CRITICAL,
            "HIGH": COLOR_HIGH,
            "MEDIUM": COLOR_MEDIUM,
            "LOW": COLOR_LOW,
            "SECURE": COLOR_SECURE
        }.get(risk_level, COLOR_MEDIUM)

        exec_data = [
            [
                Paragraph("<b>Overall Security Posture:</b>", styles["MetaText"]),
                Paragraph(f"<b><font color='{badge_color.hexval()}'>{risk_level}</font></b> (Risk Score: {risk_score}/100)", styles["MetaText"]),
            ],
            [
                Paragraph("<b>Total Issues Discovered:</b>", styles["MetaText"]),
                Paragraph(f"{scan_data.get('total_vulnerabilities', len(findings))} Vulnerability Findings", styles["MetaText"]),
            ],
            [
                Paragraph("<b>Foundry Property Fuzzing:</b>", styles["MetaText"]),
                Paragraph(f"{scan_data.get('fuzz_passed', 0)} Passed / {scan_data.get('fuzz_total', 0)} Invariants Executed", styles["MetaText"]),
            ]
        ]
        exec_table = Table(exec_data, colWidths=[160, 360])
        exec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FFFFFF")),
            ('BOX', (0, 0), (-1, -1), 1, badge_color),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(exec_table)
        story.append(Spacer(1, 10))

        # Severity Distribution Chart
        counts = {
            "CRITICAL": scan_data.get("critical_count", 0),
            "HIGH": scan_data.get("high_count", 0),
            "MEDIUM": scan_data.get("medium_count", 0),
            "LOW": scan_data.get("low_count", 0),
            "INFORMATIONAL": scan_data.get("info_count", 0),
        }
        chart_drawing = create_severity_distribution_bar(counts, width=520, height=20)
        story.append(chart_drawing)
        story.append(Spacer(1, 15))

        # Vulnerabilities Catalog
        story.append(Paragraph(f"Vulnerability Findings Detail ({len(findings)})", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0"), spaceAfter=10))

        if not findings:
            story.append(Paragraph("No critical or high-risk security vulnerabilities were identified in the analyzed contract code.", styles["MetaText"]))
        else:
            for idx, f in enumerate(findings, start=1):
                f_sev = f.get("severity", "MEDIUM")
                f_color = {
                    "CRITICAL": "#DC2626",
                    "HIGH": "#EA580C",
                    "MEDIUM": "#D97706",
                    "LOW": "#2563EB",
                    "INFORMATIONAL": "#475569"
                }.get(f_sev, "#2563EB")

                f_elements = []
                f_elements.append(Paragraph(
                    f"<b>Finding #{idx}: {f.get('title')}</b>",
                    styles["FindingTitle"]
                ))

                cwe_swc = f" | {f.get('cwe_id')}" if f.get("cwe_id") else ""
                if f.get("swc_id"):
                    cwe_swc += f" | {f.get('swc_id')}"

                meta_line = (
                    f"<b>Severity:</b> <font color='{f_color}'><b>{f_sev}</b></font> (CVSS {f.get('cvss_score', 'N/A')}) | "
                    f"<b>Category:</b> {f.get('category')} | <b>Engine:</b> {f.get('engine')}{cwe_swc}"
                )
                f_elements.append(Paragraph(meta_line, styles["MetaText"]))
                f_elements.append(Spacer(1, 4))

                # Description
                desc_p = Paragraph(f"<b>Description:</b> {f.get('description', '')}", styles["MetaText"])
                f_elements.append(desc_p)
                f_elements.append(Spacer(1, 4))

                # Code snippet
                snippet = f.get("code_snippet")
                if snippet:
                    f_elements.append(Paragraph(f"<b>Vulnerable Code (Lines {f.get('line_start', '?')}-{f.get('line_end', '?')}):</b>", styles["MetaText"]))
                    clean_snip = snippet.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
                    f_elements.append(Paragraph(clean_snip, styles["CodeBlock"]))

                # Recommendation
                f_elements.append(Paragraph(f"<b>Remediation Recommendation:</b><br/>{f.get('recommendation', '')}", styles["MetaText"]))
                f_elements.append(Spacer(1, 10))
                f_elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E2E8F0"), spaceAfter=10))

                story.append(KeepTogether(f_elements))

        # Foundry Property Fuzz Testing Results
        if fuzz_details and fuzz_details.get("tests"):
            story.append(Spacer(1, 10))
            story.append(Paragraph("Automated Foundry Dynamic Fuzz Invariants", styles["SectionHeading"]))
            fuzz_rows = [
                [
                    Paragraph("<b>Property Invariant</b>", styles["MetaText"]),
                    Paragraph("<b>Status</b>", styles["MetaText"]),
                    Paragraph("<b>Fuzz Runs</b>", styles["MetaText"]),
                    Paragraph("<b>Verification Result / Counterexample</b>", styles["MetaText"])
                ]
            ]
            for test in fuzz_details.get("tests", []):
                t_stat = test.get("status", "PASSED")
                t_color = "#16A34A" if t_stat == "PASSED" else "#DC2626"
                t_reason = test.get("reason", "")
                if test.get("counterexample"):
                    t_reason += f"<br/><b>Counterexample:</b> {test.get('counterexample')}"
                
                fuzz_rows.append([
                    Paragraph(test.get("name", "test"), styles["MetaText"]),
                    Paragraph(f"<font color='{t_color}'><b>{t_stat}</b></font>", styles["MetaText"]),
                    Paragraph(str(test.get("runs", 256)), styles["MetaText"]),
                    Paragraph(t_reason, styles["MetaText"])
                ])

            fuzz_table = Table(fuzz_rows, colWidths=[140, 60, 60, 260])
            fuzz_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(fuzz_table)

        # Disclaimer
        story.append(Spacer(1, 20))
        story.append(Paragraph(
            "<b>Disclaimer:</b> SecureChain Auditor utilizes multi-engine static, symbolic, and property-based fuzz analysis. "
            "Automated tools may not catch all logic bugs or economic exploit vectors. Formal verification and third-party manual peer "
            "reviews are strongly recommended before deploying contracts to mainnet environments.",
            styles["MetaText"]
        ))

        doc.build(story)
        return output_path
