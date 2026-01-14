"""Tests for network discovery."""

from argus.network.discovery import parse_targets


class TestTargetParsing:
    """Tests for target parsing."""
    
    def test_parse_single_ip(self):
        """Test parsing single IP address."""
        targets = parse_targets(['192.168.1.1'])
        assert len(targets) == 1
        assert targets[0] == '192.168.1.1'
    
    def test_parse_cidr(self):
        """Test parsing CIDR notation."""
        targets = parse_targets(['192.168.1.0/30'])
        assert len(targets) == 2  # /30 has 2 usable hosts
    
    def test_parse_multiple_targets(self):
        """Test parsing multiple targets."""
        targets = parse_targets(['192.168.1.1', '10.0.0.1'])
        assert len(targets) == 2
        assert '192.168.1.1' in targets
        assert '10.0.0.1' in targets
    
    def test_parse_deduplication(self):
        """Test that duplicate targets are removed."""
        targets = parse_targets(['192.168.1.1', '192.168.1.1'])
        assert len(targets) == 1

