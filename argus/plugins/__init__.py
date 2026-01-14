"""
Plugin registry for Argus.

Provides protocol-specific credential testing plugins for:
- SSH, FTP, Telnet, HTTP/HTTPS (original)
- Redis, MongoDB, MySQL, SNMP (extended)
"""

from .ssh import SSHPlugin
from .http import HTTPPlugin
from .ftp import FTPPlugin
from .telnet import TelnetPlugin
from .redis import RedisPlugin
from .mongodb import MongoDBPlugin
from .mysql import MySQLPlugin
from .snmp import SNMPPlugin

PLUGINS = {
    # Original protocols
    'ssh': SSHPlugin,
    'http': HTTPPlugin,
    'https': HTTPPlugin,
    'ftp': FTPPlugin,
    'telnet': TelnetPlugin,
    
    # Extended protocols (2.0)
    'redis': RedisPlugin,
    'mongodb': MongoDBPlugin,
    'mysql': MySQLPlugin,
    'snmp': SNMPPlugin,
}

# Port to plugin mapping for auto-detection
PORT_PLUGINS = {
    22: SSHPlugin,
    21: FTPPlugin,
    23: TelnetPlugin,
    80: HTTPPlugin,
    443: HTTPPlugin,
    8080: HTTPPlugin,
    8443: HTTPPlugin,
    6379: RedisPlugin,
    27017: MongoDBPlugin,
    27018: MongoDBPlugin,
    3306: MySQLPlugin,
    161: SNMPPlugin,
}


def get_plugin(service: str):
    """Get plugin class for service type."""
    return PLUGINS.get(service.lower())


def get_plugin_by_port(port: int):
    """Get plugin class by port number."""
    return PORT_PLUGINS.get(port)


__all__ = [
    'SSHPlugin',
    'HTTPPlugin',
    'FTPPlugin', 
    'TelnetPlugin',
    'RedisPlugin',
    'MongoDBPlugin',
    'MySQLPlugin',
    'SNMPPlugin',
    'get_plugin',
    'get_plugin_by_port',
    'PLUGINS',
    'PORT_PLUGINS',
]

