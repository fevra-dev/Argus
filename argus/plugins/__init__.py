"""
Plugin registry for Argus.

Provides protocol-specific credential testing plugins for:
- SSH, FTP, Telnet, HTTP/HTTPS (core network)
- Redis, MongoDB, MySQL, PostgreSQL (databases)
- VNC, RDP, WinRM (remote access)
- Elasticsearch, Memcached (data services)
- SNMP (network management)

Total: 14 protocols supported
"""

from .ssh import SSHPlugin
from .http import HTTPPlugin
from .ftp import FTPPlugin
from .telnet import TelnetPlugin
from .redis import RedisPlugin
from .mongodb import MongoDBPlugin
from .mysql import MySQLPlugin
from .postgresql import PostgreSQLPlugin
from .snmp import SNMPPlugin
from .vnc import VNCPlugin
from .elasticsearch import ElasticsearchPlugin
from .rdp import RDPPlugin
from .winrm import WinRMPlugin
from .memcached import MemcachedPlugin

PLUGINS = {
    # Core network protocols
    'ssh': SSHPlugin,
    'http': HTTPPlugin,
    'https': HTTPPlugin,
    'ftp': FTPPlugin,
    'telnet': TelnetPlugin,
    
    # Database protocols
    'redis': RedisPlugin,
    'mongodb': MongoDBPlugin,
    'mysql': MySQLPlugin,
    'postgresql': PostgreSQLPlugin,
    'postgres': PostgreSQLPlugin,  # Alias
    'elasticsearch': ElasticsearchPlugin,
    'elastic': ElasticsearchPlugin,  # Alias
    
    # Remote access protocols
    'vnc': VNCPlugin,
    'rdp': RDPPlugin,
    'winrm': WinRMPlugin,
    
    # Cache/data services
    'memcached': MemcachedPlugin,
    
    # Network management
    'snmp': SNMPPlugin,
}

# Port to plugin mapping for auto-detection
PORT_PLUGINS = {
    # Core network
    22: SSHPlugin,
    21: FTPPlugin,
    23: TelnetPlugin,
    80: HTTPPlugin,
    443: HTTPPlugin,
    8080: HTTPPlugin,
    8443: HTTPPlugin,
    
    # Databases
    6379: RedisPlugin,
    27017: MongoDBPlugin,
    27018: MongoDBPlugin,
    3306: MySQLPlugin,
    5432: PostgreSQLPlugin,
    9200: ElasticsearchPlugin,
    9300: ElasticsearchPlugin,
    
    # Remote access
    5900: VNCPlugin,
    5901: VNCPlugin,
    5902: VNCPlugin,
    3389: RDPPlugin,
    5985: WinRMPlugin,
    5986: WinRMPlugin,
    
    # Cache/data
    11211: MemcachedPlugin,
    
    # Network management
    161: SNMPPlugin,
}


def get_plugin(service: str):
    """Get plugin class for service type."""
    return PLUGINS.get(service.lower())


def get_plugin_by_port(port: int):
    """Get plugin class by port number."""
    return PORT_PLUGINS.get(port)


__all__ = [
    # Core network
    'SSHPlugin',
    'HTTPPlugin',
    'FTPPlugin', 
    'TelnetPlugin',
    # Databases
    'RedisPlugin',
    'MongoDBPlugin',
    'MySQLPlugin',
    'PostgreSQLPlugin',
    'ElasticsearchPlugin',
    # Remote access
    'VNCPlugin',
    'RDPPlugin',
    'WinRMPlugin',
    # Cache/data
    'MemcachedPlugin',
    # Network management
    'SNMPPlugin',
    # Helper functions
    'get_plugin',
    'get_plugin_by_port',
    'PLUGINS',
    'PORT_PLUGINS',
]

