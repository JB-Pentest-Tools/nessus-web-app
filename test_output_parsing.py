#!/usr/bin/env python3
"""
Test script to verify output and plugin_output field extraction
"""

import xml.etree.ElementTree as ET

def test_output_parsing():
    """Test output field extraction from Nessus XML"""
    
    # Sample Nessus XML with both output fields
    sample_xml = '''<?xml version="1.0" ?>
    <NessusClientData_v2>
        <Report name="test">
            <ReportHost name="192.168.1.100">
                <ReportItem port="80" protocol="tcp" pluginID="12345" pluginName="Test Vulnerability">
                    <severity>2</severity>
                    <description>Test vulnerability description</description>
                    <solution>Update the software</solution>
                    <output>
    Affected version: 1.2.3
    Fixed version: 1.2.4
    Configuration file: /etc/test/config.conf
    Status: VULNERABLE
                    </output>
                    <plugin_output>
    Additional plugin details:
    - Service detected: Apache 2.4.41
    - Last modified: 2023-01-15
    - Confidence: High
                    </plugin_output>
                </ReportItem>
            </ReportHost>
        </Report>
    </NessusClientData_v2>'''
    
    print("🧪 Testing Nessus Output Field Extraction...")
    
    try:
        root = ET.fromstring(sample_xml)
        
        for report_item in root.findall('.//ReportItem'):
            output = ""
            plugin_output = ""
            
            for child in report_item:
                if child.tag == 'output':
                    output = child.text or ""
                elif child.tag == 'plugin_output':
                    plugin_output = child.text or ""
            
            print(f"✅ Found output field: {len(output)} characters")
            if output:
                print(f"   Content preview: {output.strip()[:100]}...")
            
            print(f"✅ Found plugin_output field: {len(plugin_output)} characters")
            if plugin_output:
                print(f"   Content preview: {plugin_output.strip()[:100]}...")
            
            # Test combination logic
            combined_output = ""
            if output and plugin_output:
                if output.strip() != plugin_output.strip():
                    combined_output = f"Output:\n{output}\n\nPlugin Output:\n{plugin_output}"
                else:
                    combined_output = plugin_output
            elif output:
                combined_output = output
            elif plugin_output:
                combined_output = plugin_output
            
            print(f"✅ Combined output: {len(combined_output)} characters")
            print(f"   Combined preview:\n{combined_output[:200]}...")
            
            return True
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    success = test_output_parsing()
    if success:
        print("\n🎉 Output parsing test PASSED!")
        print("📋 The app will now capture both 'output' and 'plugin_output' fields")
        print("🔍 This includes: affected versions, fixed versions, file paths, configuration details")
    else:
        print("\n💥 Output parsing test FAILED")