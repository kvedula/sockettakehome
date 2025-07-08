#!/usr/bin/env python3
"""
Comprehensive test script for dependency scanners
"""
import unittest
import json
import os
import sys
from unittest.mock import patch, MagicMock
from enhanced_scanner import EnhancedDependencyScanner

class TestEnhancedDependencyScanner(unittest.TestCase):
    
    def setUp(self):
        self.scanner = EnhancedDependencyScanner("test_requirements.txt")
    
    def test_parse_requirements(self):
        # Create a temporary requirements file for testing
        test_content = """requests==2.25.1
django>=3.0.0
flask
# this is a comment
numpy==1.21.0"""
        
        with open("temp_requirements.txt", "w") as f:
            f.write(test_content)
        
        temp_scanner = EnhancedDependencyScanner("temp_requirements.txt")
        deps = temp_scanner.parse_requirements()
        
        self.assertEqual(len(deps), 4)  # 4 non-comment lines
        self.assertEqual(deps[0]['name'], 'requests')
        self.assertEqual(deps[0]['version'], '2.25.1')
        self.assertEqual(deps[0]['operator'], '==')
        
        self.assertEqual(deps[1]['name'], 'django')
        self.assertEqual(deps[1]['version'], '3.0.0')
        self.assertEqual(deps[1]['operator'], '>=')
        
        self.assertEqual(deps[2]['name'], 'flask')
        self.assertIsNone(deps[2]['version'])
        
        # Cleanup
        os.remove("temp_requirements.txt")
    
    @patch('enhanced_scanner.requests.post')
    def test_check_vulnerabilities_with_vulns(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'vulnerabilities': [
                {
                    'id': 'CVE-2023-12345',
                    'summary': 'Test vulnerability',
                    'database_specific': {'severity': 'HIGH'}
                }
            ]
        }
        mock_post.return_value = mock_response
        
        test_deps = [
            {'name': 'requests', 'version': '2.25.1', 'original_line': 'requests==2.25.1'}
        ]
        
        vulnerabilities = self.scanner.check_vulnerabilities(test_deps)
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['id'], 'CVE-2023-12345')
        self.assertEqual(vulnerabilities[0]['affected_package']['name'], 'requests')
    
    @patch('enhanced_scanner.requests.post')
    def test_check_vulnerabilities_no_vulns(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_post.return_value = mock_response
        
        test_deps = [
            {'name': 'requests', 'version': '2.25.1', 'original_line': 'requests==2.25.1'}
        ]
        
        vulnerabilities = self.scanner.check_vulnerabilities(test_deps)
        
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_severity_breakdown(self):
        test_vulnerabilities = [
            {
                'database_specific': {'severity': 'HIGH'},
                'affected_package': {'name': 'test1', 'version': '1.0.0'}
            },
            {
                'database_specific': {'severity': 'MEDIUM'},
                'affected_package': {'name': 'test2', 'version': '2.0.0'}
            },
            {
                'severity': 'LOW',
                'affected_package': {'name': 'test3', 'version': '3.0.0'}
            }
        ]
        
        breakdown = self.scanner._get_severity_breakdown(test_vulnerabilities)
        
        self.assertEqual(breakdown['HIGH'], 1)
        self.assertEqual(breakdown['MEDIUM'], 1)
        self.assertEqual(breakdown['LOW'], 1)
        self.assertEqual(breakdown['CRITICAL'], 0)
    
    def test_generate_json_report(self):
        test_vulnerabilities = [
            {
                'id': 'CVE-2023-12345',
                'database_specific': {'severity': 'HIGH'},
                'summary': 'Test vulnerability',
                'affected_package': {'name': 'test-package', 'version': '1.0.0'}
            }
        ]
        
        test_dependencies = [
            {'name': 'test-package', 'version': '1.0.0', 'operator': '=='}
        ]
        
        self.scanner.generate_json_report(test_vulnerabilities, test_dependencies)
        
        # Check if JSON file was created
        self.assertTrue(os.path.exists("vulnerability_report.json"))
        
        # Check JSON content
        with open("vulnerability_report.json", "r") as f:
            report = json.load(f)
            self.assertEqual(len(report['vulnerabilities']), 1)
            self.assertEqual(report['vulnerabilities'][0]['id'], 'CVE-2023-12345')
            self.assertIn('scan_info', report)
            self.assertIn('summary', report)
            self.assertIn('dependencies', report)
        
        # Cleanup
        os.remove("vulnerability_report.json")

def run_integration_test():
    """Run an integration test with the enhanced scanner"""
    print("Running integration test...")
    print("="*50)
    
    # Test the enhanced scanner
    if os.path.exists("test_requirements.txt"):
        print("✅ Test requirements file exists")
        
        scanner = EnhancedDependencyScanner("test_requirements.txt")
        deps = scanner.parse_requirements()
        
        print(f"✅ Parsed {len(deps)} dependencies")
        
        # Just test parsing without calling the API to avoid network issues
        for dep in deps:
            print(f"   - {dep['name']}: {dep['version']}")
        
        print("✅ Integration test passed!")
    else:
        print("❌ Test requirements file not found")

if __name__ == '__main__':
    print("Running unit tests...")
    unittest.main(argv=[''], exit=False)
    
    print("\n" + "="*50)
    run_integration_test()
