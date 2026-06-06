"""JSON report exporter."""
import os
from vulnscan5g.models.scan_result import ScanResult


def save_json(result: ScanResult, output_path: str):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(result.to_json())
