"""Reporting module: standardized templates and markdown bug bounty report generation."""

from .templates import REPORT_TEMPLATE
from .report_generator import ReportGenerator

__all__ = [
    "REPORT_TEMPLATE",
    "ReportGenerator",
]
