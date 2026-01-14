"""Tests for credential testing plugins."""

import pytest
from argus.plugins.ssh import SSHPlugin
from argus.plugins.http import HTTPPlugin
from argus.plugins.ftp import FTPPlugin
from argus.plugins.telnet import TelnetPlugin
from argus.models import Credential


class TestSSHPlugin:
    """Tests for SSH plugin."""
    
    def test_plugin_initialization(self):
        """Test SSH plugin initializes correctly."""
        plugin = SSHPlugin(timeout=5)
        assert plugin.SERVICE_NAME == "ssh"
        assert plugin.DEFAULT_PORT == 22
        assert plugin.timeout == 5
    
    def test_get_access_level(self):
        """Test access level determination."""
        plugin = SSHPlugin()
        
        assert plugin.get_access_level("admin") == "admin"
        assert plugin.get_access_level("root") == "admin"
        assert plugin.get_access_level("administrator") == "admin"
        assert plugin.get_access_level("user") == "user"
        assert plugin.get_access_level("guest") == "guest"


class TestHTTPPlugin:
    """Tests for HTTP plugin."""
    
    def test_plugin_initialization(self):
        """Test HTTP plugin initializes correctly."""
        plugin = HTTPPlugin(timeout=5)
        assert plugin.SERVICE_NAME == "http"
        assert plugin.DEFAULT_PORT == 80
        assert plugin.timeout == 5
    
    def test_auth_paths_exist(self):
        """Test that auth paths are defined."""
        plugin = HTTPPlugin()
        assert len(plugin.AUTH_PATHS) > 0
        assert "/" in plugin.AUTH_PATHS
        assert "/admin" in plugin.AUTH_PATHS


class TestFTPPlugin:
    """Tests for FTP plugin."""
    
    def test_plugin_initialization(self):
        """Test FTP plugin initializes correctly."""
        plugin = FTPPlugin(timeout=5)
        assert plugin.SERVICE_NAME == "ftp"
        assert plugin.DEFAULT_PORT == 21
        assert plugin.timeout == 5


class TestTelnetPlugin:
    """Tests for Telnet plugin."""
    
    def test_plugin_initialization(self):
        """Test Telnet plugin initializes correctly."""
        plugin = TelnetPlugin(timeout=5)
        assert plugin.SERVICE_NAME == "telnet"
        assert plugin.DEFAULT_PORT == 23
        assert plugin.timeout == 5

