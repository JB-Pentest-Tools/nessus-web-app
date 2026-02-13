#!/usr/bin/env python3
"""
Nessus Output Parsers
Intelligent parsing of vulnerability output fields to extract structured data

Author: Dave (OpenClaw)
Created: 2026-02-13
"""

import re
from typing import Dict, List, Optional, Tuple, Any
import json

class VulnerabilityParser:
    """Base class for vulnerability output parsing"""
    
    def __init__(self):
        self.patterns = {}
        self.confidence_threshold = 0.7
    
    def parse(self, output: str, plugin_name: str = "", severity: str = "") -> Dict[str, Any]:
        """Parse vulnerability output and return structured data"""
        raise NotImplementedError
    
    def get_confidence(self, output: str, plugin_name: str = "") -> float:
        """Return confidence score (0.0 - 1.0) for this parser"""
        raise NotImplementedError
    
    def extract_field(self, output: str, pattern: str, group: int = 1) -> Optional[str]:
        """Extract a specific field using regex pattern"""
        match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
        return match.group(group) if match else None

class LinuxPackageParser(VulnerabilityParser):
    """Parser for Linux package vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'remote_package': r'Remote package installed\s*:\s*([^\s]+)-([^\s]+)',
            'should_be_package': r'Should be\s*:\s*([^\s]+)-([^\s]+)',
            'package_name': r'Remote package installed\s*:\s*([^-\s]+)',
            'installed_version': r'Remote package installed\s*:\s*[^-\s]+-([^\s]+)',
            'fixed_version': r'Should be\s*:\s*[^-\s]+-([^\s]+)',
            'advisory_id': r'(RHSA-\d{4}:\d+|USN-\d+-\d+|DSA-\d+-\d+)',
            'cve_list': r'(CVE-\d{4}-\d+)',
        }
    
    def get_confidence(self, output: str, plugin_name: str = "") -> float:
        """Calculate confidence for Linux package parsing"""
        confidence = 0.0
        
        # Check for Linux indicators
        linux_indicators = [
            'Remote package installed',
            'Should be',
            'RHSA-', 'USN-', 'DSA-',
            'rpm', 'deb', 'yum', 'apt'
        ]
        
        for indicator in linux_indicators:
            if indicator.lower() in output.lower():
                confidence += 0.2
                
        # Check plugin name for Linux indicators
        if plugin_name:
            linux_os = ['RHEL', 'CentOS', 'Ubuntu', 'Debian', 'SUSE']
            for os_name in linux_os:
                if os_name.lower() in plugin_name.lower():
                    confidence += 0.3
                    break
        
        return min(confidence, 1.0)
    
    def parse(self, output: str, plugin_name: str = "", severity: str = "") -> Dict[str, Any]:
        """Parse Linux package vulnerability output"""
        result = {
            'parser_type': 'linux_package',
            'confidence': self.get_confidence(output, plugin_name),
            'packages': [],
            'advisory_id': None,
            'cves': []
        }
        
        # Extract advisory ID
        result['advisory_id'] = self.extract_field(output, self.patterns['advisory_id'])
        
        # If no advisory found in output, try plugin name
        if not result['advisory_id'] and plugin_name:
            result['advisory_id'] = self.extract_field(plugin_name, self.patterns['advisory_id'])
        
        # Extract CVEs
        cves = re.findall(self.patterns['cve_list'], output, re.IGNORECASE)
        result['cves'] = list(set(cves))
        
        # Extract package information
        # Split output into lines and parse each package entry
        lines = output.split('\n')
        current_package = {}
        
        for line in lines:
            line = line.strip()
            
            # Remote package installed
            remote_match = re.search(self.patterns['remote_package'], line)
            if remote_match:
                if current_package:  # Save previous package
                    result['packages'].append(current_package)
                
                current_package = {
                    'name': remote_match.group(1),
                    'installed_version': remote_match.group(2),
                    'fixed_version': None,
                    'full_installed': remote_match.group(0)
                }
            
            # Should be version
            should_be_match = re.search(self.patterns['should_be_package'], line)
            if should_be_match and current_package:
                current_package['fixed_version'] = should_be_match.group(2)
                current_package['full_fixed'] = should_be_match.group(0)
        
        # Don't forget the last package
        if current_package:
            result['packages'].append(current_package)
        
        # If no packages found, try to extract at least the package name from plugin name
        if not result['packages'] and plugin_name:
            package_match = re.search(r':\s*([^\s\(]+)', plugin_name)
            if package_match:
                result['packages'].append({
                    'name': package_match.group(1),
                    'installed_version': 'Unknown',
                    'fixed_version': 'See advisory',
                    'full_installed': 'Unknown',
                    'full_fixed': 'See advisory'
                })
        
        return result

class WindowsUpdateParser(VulnerabilityParser):
    """Parser for Windows update vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'kb_number': r'(KB\d+)',
            'ms_bulletin': r'(MS\d{2}-\d+)',
            'missing_update': r'Missing update\s*:\s*([^\n]+)',
            'update_level': r'Update Level\s*:\s*([^\n]+)',
        }
    
    def get_confidence(self, output: str, plugin_name: str = "") -> float:
        """Calculate confidence for Windows update parsing"""
        confidence = 0.0
        
        windows_indicators = [
            'KB', 'Microsoft', 'Windows', 'MS17-', 'MS16-',
            'Missing update', 'Update Level', 'hotfix'
        ]
        
        for indicator in windows_indicators:
            if indicator.lower() in output.lower() or (plugin_name and indicator.lower() in plugin_name.lower()):
                confidence += 0.25
                
        return min(confidence, 1.0)
    
    def parse(self, output: str, plugin_name: str = "", severity: str = "") -> Dict[str, Any]:
        """Parse Windows update vulnerability output"""
        result = {
            'parser_type': 'windows_update',
            'confidence': self.get_confidence(output, plugin_name),
            'kb_numbers': [],
            'ms_bulletins': [],
            'missing_updates': [],
            'update_level': None
        }
        
        # Extract KB numbers
        kb_matches = re.findall(self.patterns['kb_number'], output, re.IGNORECASE)
        result['kb_numbers'] = list(set(kb_matches))
        
        # Extract MS bulletins
        ms_matches = re.findall(self.patterns['ms_bulletin'], output, re.IGNORECASE)
        result['ms_bulletins'] = list(set(ms_matches))
        
        # Extract missing updates
        missing_updates = re.findall(self.patterns['missing_update'], output, re.IGNORECASE)
        result['missing_updates'] = missing_updates
        
        # Extract update level
        result['update_level'] = self.extract_field(output, self.patterns['update_level'])
        
        return result

class WebVulnerabilityParser(VulnerabilityParser):
    """Parser for web application vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'url': r'https?://[^\s<>"]+',
            'parameter': r'Parameter\s*:\s*([^\n]+)',
            'method': r'Method\s*:\s*(GET|POST|PUT|DELETE|PATCH)',
            'payload': r'Payload\s*:\s*([^\n]+)',
        }
    
    def get_confidence(self, output: str, plugin_name: str = "") -> float:
        """Calculate confidence for web vulnerability parsing"""
        confidence = 0.0
        
        web_indicators = [
            'http://', 'https://', 'Parameter:', 'Method:',
            'XSS', 'SQL', 'CSRF', 'injection'
        ]
        
        for indicator in web_indicators:
            if indicator.lower() in output.lower() or (plugin_name and indicator.lower() in plugin_name.lower()):
                confidence += 0.2
                
        return min(confidence, 1.0)
    
    def parse(self, output: str, plugin_name: str = "", severity: str = "") -> Dict[str, Any]:
        """Parse web vulnerability output"""
        result = {
            'parser_type': 'web_vulnerability',
            'confidence': self.get_confidence(output, plugin_name),
            'urls': [],
            'parameters': [],
            'methods': [],
            'payloads': []
        }
        
        # Extract URLs
        urls = re.findall(self.patterns['url'], output)
        result['urls'] = list(set(urls))
        
        # Extract parameters
        parameters = re.findall(self.patterns['parameter'], output, re.IGNORECASE)
        result['parameters'] = parameters
        
        # Extract methods
        methods = re.findall(self.patterns['method'], output, re.IGNORECASE)
        result['methods'] = list(set(methods))
        
        # Extract payloads
        payloads = re.findall(self.patterns['payload'], output, re.IGNORECASE)
        result['payloads'] = payloads
        
        return result

class ServiceVulnerabilityParser(VulnerabilityParser):
    """Parser for network service vulnerabilities"""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'service_version': r'Version\s*:\s*([^\n]+)',
            'banner': r'Banner\s*:\s*([^\n]+)',
            'protocol': r'Protocol\s*:\s*(TCP|UDP)',
        }
    
    def get_confidence(self, output: str, plugin_name: str = "") -> float:
        """Calculate confidence for service vulnerability parsing"""
        confidence = 0.0
        
        service_indicators = [
            'Version:', 'Banner:', 'Protocol:', 'Service:',
            'listening', 'running', 'detected'
        ]
        
        for indicator in service_indicators:
            if indicator.lower() in output.lower():
                confidence += 0.2
                
        return min(confidence, 1.0)
    
    def parse(self, output: str, plugin_name: str = "", severity: str = "") -> Dict[str, Any]:
        """Parse service vulnerability output"""
        result = {
            'parser_type': 'service_vulnerability',
            'confidence': self.get_confidence(output, plugin_name),
            'version': None,
            'banner': None,
            'protocol': None
        }
        
        # Extract version
        result['version'] = self.extract_field(output, self.patterns['service_version'])
        
        # Extract banner
        result['banner'] = self.extract_field(output, self.patterns['banner'])
        
        # Extract protocol
        result['protocol'] = self.extract_field(output, self.patterns['protocol'])
        
        return result

class ParsedOutputManager:
    """Manages multiple parsers and selects the best one for each vulnerability"""
    
    def __init__(self):
        self.parsers = [
            LinuxPackageParser(),
            WindowsUpdateParser(),
            WebVulnerabilityParser(),
            ServiceVulnerabilityParser()
        ]
    
    def parse_vulnerability(self, plugin_output: str, plugin_name: str = "", severity: str = "") -> Dict[str, Any]:
        """Parse vulnerability output using the best available parser"""
        best_parser = None
        best_confidence = 0.0
        best_result = None
        
        # Try each parser and find the one with highest confidence
        for parser in self.parsers:
            confidence = parser.get_confidence(plugin_output, plugin_name)
            if confidence > best_confidence:
                best_confidence = confidence
                best_parser = parser
        
        # If we found a good parser (confidence > threshold), use it
        if best_parser and best_confidence >= best_parser.confidence_threshold:
            best_result = best_parser.parse(plugin_output, plugin_name, severity)
        else:
            # Fallback to generic parsing
            best_result = {
                'parser_type': 'generic',
                'confidence': 0.0,
                'raw_output': plugin_output,
                'plugin_name': plugin_name,
                'severity': severity
            }
        
        return best_result
    
    def get_available_columns(self, parser_type: str = 'all') -> List[Dict[str, str]]:
        """Get available columns for CSV export based on parser type"""
        
        base_columns = [
            {'key': 'host_ip', 'name': 'IP Address', 'description': 'Host IP address'},
            {'key': 'host_fqdn', 'name': 'FQDN/Hostname', 'description': 'Fully qualified domain name'},
            {'key': 'plugin_name', 'name': 'Issue Title', 'description': 'Vulnerability title'},
            {'key': 'severity', 'name': 'Severity', 'description': 'Vulnerability severity'},
            {'key': 'cvss_score', 'name': 'CVSS Score', 'description': 'CVSS base score'},
            {'key': 'port', 'name': 'Port', 'description': 'Affected port'},
            {'key': 'protocol', 'name': 'Protocol', 'description': 'Network protocol'},
            {'key': 'service_name', 'name': 'Service', 'description': 'Service name'},
        ]
        
        parser_specific = {
            'linux_package': [
                {'key': 'package_name', 'name': 'Package Name', 'description': 'Affected package name'},
                {'key': 'installed_version', 'name': 'Installed Version', 'description': 'Currently installed version'},
                {'key': 'fixed_version', 'name': 'Fixed Version', 'description': 'Version that fixes the vulnerability'},
                {'key': 'advisory_id', 'name': 'Advisory ID', 'description': 'Security advisory identifier'},
                {'key': 'cves', 'name': 'CVEs', 'description': 'Associated CVE numbers'},
            ],
            'windows_update': [
                {'key': 'kb_numbers', 'name': 'KB Numbers', 'description': 'Microsoft Knowledge Base numbers'},
                {'key': 'ms_bulletins', 'name': 'MS Bulletins', 'description': 'Microsoft Security Bulletins'},
                {'key': 'missing_updates', 'name': 'Missing Updates', 'description': 'Required security updates'},
                {'key': 'update_level', 'name': 'Update Level', 'description': 'System update level'},
            ],
            'web_vulnerability': [
                {'key': 'urls', 'name': 'URLs', 'description': 'Affected URLs'},
                {'key': 'parameters', 'name': 'Parameters', 'description': 'Vulnerable parameters'},
                {'key': 'methods', 'name': 'HTTP Methods', 'description': 'HTTP methods involved'},
                {'key': 'payloads', 'name': 'Payloads', 'description': 'Attack payloads used'},
            ],
            'service_vulnerability': [
                {'key': 'service_version', 'name': 'Service Version', 'description': 'Detected service version'},
                {'key': 'service_banner', 'name': 'Service Banner', 'description': 'Service banner information'},
                {'key': 'service_protocol', 'name': 'Service Protocol', 'description': 'Network protocol used'},
            ]
        }
        
        if parser_type == 'all':
            all_columns = base_columns.copy()
            for columns in parser_specific.values():
                all_columns.extend(columns)
            return all_columns
        else:
            return base_columns + parser_specific.get(parser_type, [])
    
    def format_for_export(self, parsed_data: Dict[str, Any], selected_columns: List[str]) -> Dict[str, str]:
        """Format parsed data for CSV export based on selected columns"""
        result = {}
        
        # Only format parsed fields, not database fields
        parsed_fields = ['package_name', 'installed_version', 'fixed_version', 'advisory_id', 'cves', 
                        'kb_numbers', 'ms_bulletins', 'missing_updates', 'update_level',
                        'urls', 'parameters', 'methods', 'payloads',
                        'service_version', 'service_banner', 'service_protocol']
        
        # Map parsed data to export columns
        for column in selected_columns:
            # Skip database fields - they'll be handled elsewhere
            if column not in parsed_fields:
                continue
                
            value = ""
            
            if parsed_data.get('parser_type') == 'linux_package':
                if column == 'package_name' and parsed_data.get('packages'):
                    value = ', '.join([pkg.get('name', '') for pkg in parsed_data['packages']])
                elif column == 'installed_version' and parsed_data.get('packages'):
                    value = ', '.join([pkg.get('installed_version', '') for pkg in parsed_data['packages']])
                elif column == 'fixed_version' and parsed_data.get('packages'):
                    value = ', '.join([pkg.get('fixed_version', '') for pkg in parsed_data['packages']])
                elif column == 'advisory_id':
                    value = parsed_data.get('advisory_id', '')
                elif column == 'cves':
                    value = ', '.join(parsed_data.get('cves', []))
            
            elif parsed_data.get('parser_type') == 'windows_update':
                if column == 'kb_numbers':
                    value = ', '.join(parsed_data.get('kb_numbers', []))
                elif column == 'ms_bulletins':
                    value = ', '.join(parsed_data.get('ms_bulletins', []))
                elif column == 'missing_updates':
                    value = ', '.join(parsed_data.get('missing_updates', []))
                elif column == 'update_level':
                    value = parsed_data.get('update_level', '')
            
            elif parsed_data.get('parser_type') == 'web_vulnerability':
                if column == 'urls':
                    value = ', '.join(parsed_data.get('urls', []))
                elif column == 'parameters':
                    value = ', '.join(parsed_data.get('parameters', []))
                elif column == 'methods':
                    value = ', '.join(parsed_data.get('methods', []))
                elif column == 'payloads':
                    value = ', '.join(parsed_data.get('payloads', []))
            
            elif parsed_data.get('parser_type') == 'service_vulnerability':
                if column == 'service_version':
                    value = parsed_data.get('version', '')
                elif column == 'service_banner':
                    value = parsed_data.get('banner', '')
                elif column == 'service_protocol':
                    value = parsed_data.get('protocol', '')
            
            result[column] = str(value) if value else ""
        
        return result

# Global parser manager instance
parser_manager = ParsedOutputManager()