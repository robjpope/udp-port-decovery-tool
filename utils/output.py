import json
import csv
import sys
from typing import List, Dict, Any
from datetime import datetime

class OutputFormatter:
    """Handle different output formats for scan results"""

    def __init__(self, format_type: str = 'text'):
        self.format = format_type.lower()

    def to_json(self, results: List[Dict[str, Any]]) -> str:
        """Convert results to JSON format"""
        output = {
            'scan_time': datetime.now().isoformat(),
            'total_services': len(results),
            'services': results
        }
        return json.dumps(output, indent=2, default=str)

    def to_csv(self, results: List[Dict[str, Any]]) -> None:
        """Output results in CSV format"""
        if not results:
            return

        # Determine all unique fields
        fields = set()
        for result in results:
            fields.update(result.keys())
            if 'details' in result and result['details']:
                fields.update(f"details_{k}" for k in result['details'].keys())

        fields = sorted(list(fields))

        writer = csv.DictWriter(sys.stdout, fieldnames=fields)
        writer.writeheader()

        for result in results:
            row = dict(result)
            # Flatten details
            if 'details' in row and row['details']:
                for key, value in row['details'].items():
                    row[f"details_{key}"] = value
                del row['details']
            writer.writerow(row)

    def to_text(self, results: List[Dict[str, Any]]) -> str:
        """Convert results to readable text format"""
        if not results:
            return "No responsive services found."

        output = []
        output.append(f"\n{'=' * 60}")
        output.append(f"Found {len(results)} responsive UDP services")
        output.append(f"{'=' * 60}\n")

        for result in results:
            output.append(f"[+] {result['target']}:{result['port']} - {result.get('service', 'Unknown')}")

            if result.get('status') != 'open':
                output.append(f"    Status: {result['status']}")

            if 'details' in result and result['details']:
                for key, value in result['details'].items():
                    output.append(f"    {key}: {value}")

            output.append("")  # Empty line between services

        return "\n".join(output)