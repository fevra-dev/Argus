"""JSON output reporter."""

import json
from dataclasses import asdict
from ..models import ScanResult, Service, Severity


class JSONReporter:
    def generate(self, result: ScanResult) -> str:
        def serialize(obj):
            if isinstance(obj, (Service, Severity)):
                return obj.value
            raise TypeError(f"Not serializable: {type(obj)}")
        
        return json.dumps(asdict(result), default=serialize, indent=2)

