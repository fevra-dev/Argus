"""Tests for credential database."""

from argus.credentials.database import CredentialDatabase


class TestCredentialDatabase:
    """Tests for credential database."""
    
    def test_database_initialization(self):
        """Test database loads default credentials."""
        db = CredentialDatabase()
        assert len(db.credentials) > 0
    
    def test_get_credentials_for_service(self):
        """Test getting credentials for specific service."""
        db = CredentialDatabase()
        
        ssh_creds = db.get_for_service('ssh')
        assert len(ssh_creds) > 0
        
        http_creds = db.get_for_service('http')
        assert len(http_creds) > 0
    
    def test_get_credentials_filtering(self):
        """Test credential filtering by category."""
        db = CredentialDatabase()
        
        generic_creds = db.get_credentials(categories=['generic'])
        assert len(generic_creds) > 0
        
        router_creds = db.get_credentials(categories=['routers'])
        assert len(router_creds) > 0

