"""
Credential database loader and manager.
"""

import json
from pathlib import Path
from typing import List, Optional
import logging

from ..models import Credential

logger = logging.getLogger(__name__)


class CredentialDatabase:
    """Manages credential sets for testing."""
    
    def __init__(self, custom_file: Optional[str] = None):
        """
        Initialize credential database.
        
        Args:
            custom_file: Path to custom credentials JSON file
        """
        self.credentials: dict = {}
        
        # Load default credentials
        default_path = Path(__file__).parent / "defaults.json"
        if default_path.exists():
            self._load_file(default_path)
            logger.info(f"Loaded default credentials: {sum(len(v) for v in self.credentials.values())} entries")
        
        # Load custom credentials (override/extend)
        if custom_file:
            self._load_file(Path(custom_file))
            logger.info(f"Loaded custom credentials from {custom_file}")
    
    def _load_file(self, path: Path):
        """Load credentials from JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)
        
        for category, creds in data.items():
            if category not in self.credentials:
                self.credentials[category] = []
            
            for cred in creds:
                self.credentials[category].append(Credential(
                    username=cred['username'],
                    password=cred['password'],
                    category=category,
                    vendor=cred.get('vendor', ''),
                    description=cred.get('description', '')
                ))
    
    def get_credentials(
        self,
        categories: List[str] = None,
        vendor: str = None
    ) -> List[Credential]:
        """
        Get credentials, optionally filtered.
        
        Args:
            categories: List of categories to include (None = all)
            vendor: Filter by vendor name
            
        Returns:
            List of Credential objects
        """
        result = []
        
        cats = categories or list(self.credentials.keys())
        
        for cat in cats:
            if cat in self.credentials:
                for cred in self.credentials[cat]:
                    if vendor and vendor.lower() not in cred.vendor.lower():
                        continue
                    result.append(cred)
        
        # Deduplicate by username/password
        seen = set()
        unique = []
        for cred in result:
            key = (cred.username, cred.password)
            if key not in seen:
                seen.add(key)
                unique.append(cred)
        
        return unique
    
    def get_for_service(self, service: str, vendor: str = None) -> List[Credential]:
        """Get credentials appropriate for a service type."""
        service_categories = {
            'ssh': ['generic', 'iot', 'routers'],
            'http': ['generic', 'web', 'routers', 'cameras', 'printers'],
            'https': ['generic', 'web', 'routers', 'cameras', 'printers'],
            'ftp': ['generic', 'routers', 'iot'],
            'telnet': ['generic', 'routers', 'iot'],
        }
        
        categories = service_categories.get(service.lower(), ['generic'])
        return self.get_credentials(categories=categories, vendor=vendor)

