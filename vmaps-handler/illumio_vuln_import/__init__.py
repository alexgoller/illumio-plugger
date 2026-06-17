"""illumio_vuln_import — Python port of the illumio-cli vulnerability-map import.

Reconstructed from illumio-cli 3.0.537 (compiled Ruby). Prototype intended to be
folded into github.com/alexgoller/illumio-plugger.

Two families of processors, both ending in the same PCE upload:
  * file processors  - parse a saved scan export (process_report)
  * api processors   - pull live from the scanner's API (download_vuln_data)
"""

from .base import ReportProcessorBase, get_protocol_num, get_score
from .nessus import NessusProXMLReportProcessor
from .pce_client import PCEClient, PCEError
from .qualys import QualysAPIProcessor, QualysXMLReportProcessor
from .tenable import (
    TenableIOAPIReportProcessor,
    TenableIOCSVReportProcessor,
    TenableSCAPIReportProcessor,
    TenableSCCSVReportProcessor,
)

__all__ = [
    "ReportProcessorBase",
    "PCEClient",
    "PCEError",
    "NessusProXMLReportProcessor",
    "QualysXMLReportProcessor",
    "QualysAPIProcessor",
    "TenableSCCSVReportProcessor",
    "TenableIOCSVReportProcessor",
    "TenableSCAPIReportProcessor",
    "TenableIOAPIReportProcessor",
    "get_score",
    "get_protocol_num",
    "FILE_PROCESSORS",
    "API_PROCESSORS",
    "PROCESSORS",
]

# scanner key -> processor class (parse a saved export file)
FILE_PROCESSORS = {
    "nessus": NessusProXMLReportProcessor,
    "qualys": QualysXMLReportProcessor,
    "tenable-sc": TenableSCCSVReportProcessor,
    "tenable-io": TenableIOCSVReportProcessor,
}

# scanner key -> processor class (pull live from the scanner API)
API_PROCESSORS = {
    "qualys-api": QualysAPIProcessor,
    "tenable-sc-api": TenableSCAPIReportProcessor,
    "tenable-io-api": TenableIOAPIReportProcessor,
}

# combined view (file + api) for callers that just want "all scanners"
PROCESSORS = {**FILE_PROCESSORS, **API_PROCESSORS}

__version__ = "0.1.0"
