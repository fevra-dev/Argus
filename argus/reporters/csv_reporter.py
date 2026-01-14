"""CSV output reporter."""

import csv
import io
from ..models import ScanResult


class CSVReporter:
    def generate(self, result: ScanResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            "host", "port", "service", "username", "password",
            "severity", "access_level", "vendor"
        ])
        
        for f in result.findings:
            writer.writerow([
                f.host, f.port, f.service.value, f.username, f.password,
                f.severity.value, f.access_level, f.vendor
            ])
        
        return output.getvalue()

