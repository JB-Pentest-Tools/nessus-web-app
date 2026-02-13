#!/usr/bin/env python3
"""
Test script for vulnerability output parsers
Tests the parsing functionality with sample vulnerability outputs

Author: Dave (OpenClaw)
Created: 2026-02-13
"""

from parsers import parser_manager, LinuxPackageParser, WindowsUpdateParser, WebVulnerabilityParser
import json

def test_linux_package_parser():
    """Test Linux package vulnerability parsing"""
    print("🧪 Testing Linux Package Parser")
    print("=" * 50)
    
    sample_output = """Remote package installed : net-snmp-libs-5.8-31.el8_10
Should be : net-snmp-libs-5.8-33.el8_10

Remote package installed : net-snmp-utils-5.8-31.el8_10
Should be : net-snmp-utils-5.8-33.el8_10

CVE-2022-44792, CVE-2022-44793"""
    
    plugin_name = "RHEL 8 : net-snmp (RHSA-2026:0750)"
    
    parser = LinuxPackageParser()
    result = parser.parse(sample_output, plugin_name)
    
    print(f"Plugin Name: {plugin_name}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Parser Type: {result['parser_type']}")
    print(f"Advisory ID: {result['advisory_id']}")
    print(f"CVEs: {result['cves']}")
    print(f"Packages found: {len(result['packages'])}")
    
    for i, pkg in enumerate(result['packages'], 1):
        print(f"  Package {i}:")
        print(f"    Name: {pkg['name']}")
        print(f"    Installed: {pkg['installed_version']}")
        print(f"    Fixed: {pkg['fixed_version']}")
    
    print("\n" + "=" * 50 + "\n")

def test_windows_update_parser():
    """Test Windows update vulnerability parsing"""
    print("🧪 Testing Windows Update Parser")
    print("=" * 50)
    
    sample_output = """Missing update : KB5012170
Update Level : Important

The following Microsoft Security Bulletins apply:
MS17-010: Security Update for Microsoft Windows SMB Server (4013389)"""
    
    plugin_name = "MS17-010: Security Update for Microsoft Windows SMB Server"
    
    parser = WindowsUpdateParser()
    result = parser.parse(sample_output, plugin_name)
    
    print(f"Plugin Name: {plugin_name}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Parser Type: {result['parser_type']}")
    print(f"KB Numbers: {result['kb_numbers']}")
    print(f"MS Bulletins: {result['ms_bulletins']}")
    print(f"Missing Updates: {result['missing_updates']}")
    print(f"Update Level: {result['update_level']}")
    
    print("\n" + "=" * 50 + "\n")

def test_web_vulnerability_parser():
    """Test web vulnerability parsing"""
    print("🧪 Testing Web Vulnerability Parser")
    print("=" * 50)
    
    sample_output = """The following XSS vulnerability was detected:

URL: https://example.com/search.php
Parameter: q
Method: GET
Payload: <script>alert('XSS')</script>"""
    
    plugin_name = "Cross-Site Scripting (XSS) Vulnerability"
    
    parser = WebVulnerabilityParser()
    result = parser.parse(sample_output, plugin_name)
    
    print(f"Plugin Name: {plugin_name}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Parser Type: {result['parser_type']}")
    print(f"URLs: {result['urls']}")
    print(f"Parameters: {result['parameters']}")
    print(f"Methods: {result['methods']}")
    print(f"Payloads: {result['payloads']}")
    
    print("\n" + "=" * 50 + "\n")

def test_auto_detection():
    """Test automatic parser detection"""
    print("🧪 Testing Automatic Parser Detection")
    print("=" * 50)
    
    test_cases = [
        {
            'output': 'Remote package installed : httpd-2.4.6-90.el7\nShould be : httpd-2.4.6-95.el7',
            'plugin_name': 'CentOS 7 : httpd (CESA-2021:4292)',
            'expected': 'linux_package'
        },
        {
            'output': 'Missing update : KB4577051\nUpdate Level : Critical',
            'plugin_name': 'Microsoft Windows Security Update',
            'expected': 'windows_update'
        },
        {
            'output': 'URL: http://test.com/login.php\nParameter: username\nMethod: POST',
            'plugin_name': 'SQL Injection Vulnerability',
            'expected': 'web_vulnerability'
        },
        {
            'output': 'Version : Apache/2.4.41\nBanner : Apache httpd 2.4.41 ((Ubuntu))',
            'plugin_name': 'Apache HTTP Server Version Detection',
            'expected': 'service_vulnerability'
        }
    ]
    
    for i, case in enumerate(test_cases, 1):
        print(f"Test Case {i}:")
        print(f"  Plugin: {case['plugin_name']}")
        print(f"  Expected: {case['expected']}")
        
        result = parser_manager.parse_vulnerability(
            case['output'], 
            case['plugin_name']
        )
        
        detected_type = result.get('parser_type', 'unknown')
        confidence = result.get('confidence', 0.0)
        
        print(f"  Detected: {detected_type} (confidence: {confidence:.2f})")
        print(f"  Match: {'✅' if detected_type == case['expected'] else '❌'}")
        print()

def test_column_availability():
    """Test available columns for different parser types"""
    print("🧪 Testing Column Availability")
    print("=" * 50)
    
    parser_types = ['all', 'linux_package', 'windows_update', 'web_vulnerability', 'service_vulnerability']
    
    for parser_type in parser_types:
        columns = parser_manager.get_available_columns(parser_type)
        print(f"{parser_type.upper()} columns ({len(columns)} total):")
        
        for col in columns:
            print(f"  - {col['key']}: {col['name']}")
            print(f"    {col['description']}")
        print()

def test_export_formatting():
    """Test export data formatting"""
    print("🧪 Testing Export Formatting")
    print("=" * 50)
    
    # Sample parsed data
    parsed_data = {
        'parser_type': 'linux_package',
        'confidence': 0.9,
        'packages': [
            {
                'name': 'openssl',
                'installed_version': '1.0.2k-19.el7',
                'fixed_version': '1.0.2k-21.el7'
            }
        ],
        'advisory_id': 'RHSA-2020:3600',
        'cves': ['CVE-2020-1967', 'CVE-2020-1971']
    }
    
    # Add some base data
    parsed_data.update({
        'host_ip': '192.168.1.100',
        'plugin_name': 'RHEL 7 : openssl (RHSA-2020:3600)',
        'severity': 'High'
    })
    
    selected_columns = ['host_ip', 'plugin_name', 'severity', 'package_name', 'installed_version', 'fixed_version', 'advisory_id', 'cves']
    
    formatted = parser_manager.format_for_export(parsed_data, selected_columns)
    
    print("Formatted export data:")
    for key, value in formatted.items():
        print(f"  {key}: {value}")

def main():
    """Run all parser tests"""
    print("🚀 Nessus Vulnerability Parser Tests")
    print("=" * 50)
    print()
    
    test_linux_package_parser()
    test_windows_update_parser()
    test_web_vulnerability_parser()
    test_auto_detection()
    test_column_availability()
    test_export_formatting()
    
    print("✅ All parser tests completed!")

if __name__ == '__main__':
    main()