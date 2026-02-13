#!/usr/bin/env python3
"""
IP Address Extractor for Nessus Data
Extracts actual IP addresses from Nessus plugin outputs

Author: Dave (OpenClaw)
Created: 2026-02-13
"""

import re
import sqlite3
from typing import Optional, List

class IPAddressExtractor:
    """Extract actual IP addresses from Nessus plugin outputs"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        # Plugins that commonly contain IP address information
        self.ip_plugins = [
            '25203',  # Enumerate IPv4 Interfaces via SSH
            '10180',  # Ping the remote host
            '11002',  # Nessus Network Interface Scan
            '170170', # Enumerate the Network Interface configuration via SSH
            '45590'   # Common Platform Enumeration (CPE)
        ]
    
    def extract_ip_from_text(self, text: str) -> Optional[str]:
        """Extract IP address from plugin output text"""
        if not text:
            return None
        
        # Regex to find IPv4 addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        # Find all IP addresses in the text
        ip_matches = re.findall(ip_pattern, text)
        
        if not ip_matches:
            return None
        
        # Filter out loopback and invalid IPs
        valid_ips = []
        for ip in ip_matches:
            # Split IP into octets
            octets = ip.split('.')
            
            # Skip if any octet is > 255 or < 0
            if any(int(octet) > 255 or int(octet) < 0 for octet in octets if octet.isdigit()):
                continue
            
            # Skip loopback addresses
            if ip.startswith('127.') or ip == '0.0.0.0':
                continue
            
            # Skip multicast and reserved ranges we don't want
            first_octet = int(octets[0])
            if first_octet in [0, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240]:
                continue
            
            valid_ips.append(ip)
        
        # Return the first valid IP found
        return valid_ips[0] if valid_ips else None
    
    def get_host_ip_address(self, host_id: int) -> Optional[str]:
        """Get the actual IP address for a host from plugin outputs"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        
        try:
            # Try to find IP address in known plugins
            for plugin_id in self.ip_plugins:
                result = conn.execute('''
                    SELECT hi.plugin_output
                    FROM host_issues hi
                    JOIN issues i ON hi.issue_id = i.id
                    WHERE hi.host_id = ? AND i.plugin_id = ?
                    LIMIT 1
                ''', (host_id, plugin_id)).fetchone()
                
                if result and result['plugin_output']:
                    ip = self.extract_ip_from_text(result['plugin_output'])
                    if ip:
                        return ip
            
            # If no IP found in specific plugins, try searching all plugin outputs for this host
            fallback_result = conn.execute('''
                SELECT hi.plugin_output
                FROM host_issues hi
                WHERE hi.host_id = ? AND hi.plugin_output IS NOT NULL
                ORDER BY CASE 
                    WHEN hi.plugin_output LIKE '%IP%' OR hi.plugin_output LIKE '%address%' THEN 1 
                    ELSE 2 
                END
                LIMIT 10
            ''', (host_id,)).fetchall()
            
            for row in fallback_result:
                ip = self.extract_ip_from_text(row['plugin_output'])
                if ip:
                    return ip
            
            return None
            
        finally:
            conn.close()
    
    def get_all_host_ips(self) -> dict:
        """Get IP addresses for all hosts"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        
        try:
            # Get all hosts
            hosts = conn.execute('SELECT id, host_ip FROM hosts').fetchall()
            
            ip_map = {}
            for host in hosts:
                actual_ip = self.get_host_ip_address(host['id'])
                ip_map[host['id']] = {
                    'original': host['host_ip'],
                    'actual_ip': actual_ip or host['host_ip'],  # Fallback to original
                    'extracted': actual_ip is not None
                }
            
            return ip_map
            
        finally:
            conn.close()

# Global IP extractor instance
def get_ip_extractor(db_path: str = 'nessus_analysis.db') -> IPAddressExtractor:
    """Get IP extractor instance"""
    return IPAddressExtractor(db_path)