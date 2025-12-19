"""
PDF Report Generator for GOS Integrity Scans

Generates executive PDF reports with:
- Integrity score visualization
- Storage impact analysis
- Cost projections
- Recommendations
- Compliance status
"""

from typing import Dict, List
import logging
from datetime import datetime
from fpdf import FPDF
import os

from ..core.models import ScanResult

logger = logging.getLogger(__name__)


class PDFReportGenerator:
    """
    Generates PDF reports for GOS integrity scan results.

    Features:
    - Professional executive report layout
    - Visual integrity scoring
    - Storage and cost impact visualization
    - Actionable recommendations
    - Compliance compliance status
    """

    def __init__(self, company_logo_path: str = None):
        self.company_logo_path = company_logo_path

    def generate_integrity_report(
        self,
        scan_result: ScanResult,
        output_path: str,
        additional_data: Dict = None
    ) -> str:
        """
        Generate comprehensive PDF integrity report.

        Args:
            scan_result: ScanResult from GOSIntegrityScanner
            output_path: Path for output PDF file
            additional_data: Additional data to include in report

        Returns:
            Path to generated PDF
        """
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Header
        self._add_header(pdf, scan_result)

        # Executive Summary
        self._add_executive_summary(pdf, scan_result)

        # Integrity Score Visualization
        self._add_integrity_score(pdf, scan_result)

        # Detailed Findings
        self._add_findings(pdf, scan_result)

        # Storage and Cost Analysis
        self._add_storage_analysis(pdf, scan_result)

        # Recommendations
        self._add_recommendations(pdf, scan_result)

        # Footer
        self._add_footer(pdf)

        # Save PDF
        pdf.output(output_path)
        logger.info(f"GOS integrity report saved to {output_path}")

        return output_path

    def _add_header(self, pdf: FPDF, scan_result: ScanResult):
        """Add report header with company info and scan details."""
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "SAP GOS Integrity Audit Report", ln=True, align="C")
        pdf.ln(5)

        pdf.set_font("Arial", "", 12)
        pdf.cell(0, 8, f"System: {scan_result.system_name}", ln=True)
        pdf.cell(0, 8, f"Client: {scan_result.client}", ln=True)
        pdf.cell(0, 8, f"Scan Date: {scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
        pdf.ln(10)

    def _add_executive_summary(self, pdf: FPDF, scan_result: ScanResult):
        """Add executive summary section."""
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Executive Summary", ln=True)
        pdf.set_font("Arial", "", 12)

        summary_text = (
            f"This GOS integrity scan analyzed SOFFCONT1 bloat in system {scan_result.system_name}, "
            f"identifying {scan_result.orphaned_cont_count:,} orphaned entries out of "
            f"{scan_result.total_soffcont1_rows:,} total records. "
            f"The integrity score of {scan_result.integrity_score}% indicates the health "
            f"of GOS object relationships. Remediation could reclaim "
            f"{scan_result.estimated_storage_mb:.2f} MB and save approximately "
            f"${scan_result.estimated_cost_usd:.2f}."
        )

        pdf.multi_cell(0, 8, summary_text)
        pdf.ln(5)

    def _add_integrity_score(self, pdf: FPDF, scan_result: ScanResult):
        """Add integrity score visualization."""
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Integrity Score", ln=True)

        # Draw score as a visual indicator
        score = scan_result.integrity_score
        pdf.set_font("Arial", "B", 48)

        # Color coding based on score
        if score >= 95:
            pdf.set_text_color(0, 128, 0)  # Green
            status = "EXCELLENT"
        elif score >= 85:
            pdf.set_text_color(255, 165, 0)  # Orange
            status = "GOOD"
        elif score >= 70:
            pdf.set_text_color(255, 140, 0)  # Dark Orange
            status = "FAIR"
        else:
            pdf.set_text_color(255, 0, 0)  # Red
            status = "POOR"

        pdf.cell(0, 20, f"{score}%", ln=True, align="C")
        pdf.set_text_color(0, 0, 0)  # Reset to black

        pdf.set_font("Arial", "I", 14)
        pdf.cell(0, 10, f"Status: {status}", ln=True, align="C")
        pdf.ln(5)

    def _add_findings(self, pdf: FPDF, scan_result: ScanResult):
        """Add detailed findings section."""
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Detailed Findings", ln=True)
        pdf.set_font("Arial", "", 12)

        findings = [
            f"Total SOFFCONT1 Records: {scan_result.total_soffcont1_rows:,}",
            f"Orphaned Physical Objects: {scan_result.orphaned_phio_count:,}",
            f"Orphaned Content Entries: {scan_result.orphaned_cont_count:,}",
            f"Integrity Coverage: {scan_result.integrity_score}%"
        ]

        for finding in findings:
            pdf.cell(0, 8, f"• {finding}", ln=True)

        pdf.ln(5)

    def _add_storage_analysis(self, pdf: FPDF, scan_result: ScanResult):
        """Add storage impact analysis."""
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Storage & Cost Impact", ln=True)
        pdf.set_font("Arial", "", 12)

        analysis = [
            f"Reclaimable Storage: {scan_result.estimated_storage_mb:.2f} MB",
            f"Estimated Cost Savings: ${scan_result.estimated_cost_usd:.2f}",
            f"Storage Efficiency: {((scan_result.total_soffcont1_rows - scan_result.orphaned_cont_count) / max(scan_result.total_soffcont1_rows, 1) * 100):.2f}%"
        ]

        for item in analysis:
            pdf.cell(0, 8, f"• {item}", ln=True)

        pdf.ln(5)

    def _add_recommendations(self, pdf: FPDF, scan_result: ScanResult):
        """Add remediation recommendations."""
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Recommendations", ln=True)
        pdf.set_font("Arial", "", 12)

        for recommendation in scan_result.recommendations:
            pdf.cell(0, 8, f"• {recommendation}", ln=True)

        pdf.ln(10)

    def _add_footer(self, pdf: FPDF):
        """Add report footer."""
        pdf.set_y(-15)
        pdf.set_font("Arial", "I", 8)
        pdf.cell(0, 10, f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 0, "C")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create a mock scan result for testing
    from datetime import datetime
    from dataclasses import dataclass

    mock_result = ScanResult(
        timestamp=datetime.now(),
        system_name="PRD",
        client="100",
        total_soffcont1_rows=100000,
        orphaned_phio_count=5000,
        orphaned_cont_count=7500,
        integrity_score=75.0,
        estimated_storage_mb=15.2,
        estimated_cost_usd=0.76,
        recommendations=[
            "HIGH PRIORITY: 7,500 orphaned entries found. Cleanup recommended.",
            "Validate findings in non-production system first.",
            "Consider Content Server migration for large documents."
        ]
    )

    generator = PDFReportGenerator()
    output_path = "./GOS_Integrity_Audit_PRD_test.pdf"

    try:
        result_path = generator.generate_integrity_report(mock_result, output_path)
        print(f"PDF report generated: {result_path}")
    except Exception as e:
        print(f"Error generating PDF: {e}")
        # If fpdf2 is not available, show what would happen
        print("PDF report would be generated with the following data:")
        print(f"System: {mock_result.system_name}")
        print(f"Integrity Score: {mock_result.integrity_score}%")
        print(f"Orphaned Entries: {mock_result.orphaned_cont_count:,}")
        print(f"Estimated Savings: ${mock_result.estimated_cost_usd:.2f}")