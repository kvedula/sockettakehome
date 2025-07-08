import unittest
import json
import os
from unittest.mock import patch, MagicMock
from scanner import DependencyScanner


class TestDependencyScanner(unittest.TestCase):
    
    def setUp(self):
        self.scanner = DependencyScanner("requirements.txt")
        self.sample_dependencies = [
            {
                "package": {
                    "package_name": "requests",
                    "installed_version": "2.28.0"
                }
            },
            {
                "package": {
                    "package_name": "flask",
                    "installed_version": "2.2.0"
                }
            }
        ]
    
    @patch('scanner.subprocess.run')
    def test_resolve_dependencies(self, mock_run):
        mock_run.return_value = MagicMock(stdout='[{"package": {"package_name": "requests", "installed_version": "2.28.0"}}]')
        result = self.scanner.resolve_dependencies()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['package']['package_name'], 'requests')
    
    @patch('scanner.requests.post')
    def test_check_vulnerabilities(self, mock_post):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {
            'vulnerabilities': [
                {
                    'id': 'CVE-2023-12345',
                    'severity': 'HIGH',
                    'summary': 'Test vulnerability'
                }
            ]
        }
        mock_post.return_value = mock_response
        
        vulnerabilities = self.scanner.check_vulnerabilities(self.sample_dependencies)
        self.assertEqual(len(vulnerabilities), 2)  # 2 dependencies queried
        self.assertEqual(vulnerabilities[0]['id'], 'CVE-2023-12345')
    
    @patch('scanner.requests.post')
    def test_check_vulnerabilities_no_vulns(self, mock_post):
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.json.return_value = {}
        mock_post.return_value = mock_response
        
        vulnerabilities = self.scanner.check_vulnerabilities(self.sample_dependencies)
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_generate_json_report(self):
        test_vulnerabilities = [
            {
                'id': 'CVE-2023-12345',
                'database_specific': {'severity': 'HIGH'},
                'summary': 'Test vulnerability',
                'affected_package': {'name': 'test-package', 'version': '1.0.0'}
            }
        ]
        
        self.scanner.generate_json_report(test_vulnerabilities, self.sample_dependencies)
        
        # Check if JSON file was created
        self.assertTrue(os.path.exists("vulnerability_report.json"))
        
        # Check JSON content
        with open("vulnerability_report.json", "r") as f:
            report = json.load(f)
            self.assertEqual(len(report['vulnerabilities']), 1)
            self.assertEqual(report['vulnerabilities'][0]['id'], 'CVE-2023-12345')
            self.assertIn('scan_info', report)
            self.assertIn('summary', report)
        
        # Cleanup
        os.remove("vulnerability_report.json")
    
    def test_severity_breakdown(self):
        test_vulnerabilities = [
            {
                'database_specific': {'severity': 'HIGH'},
                'affected_package': {'name': 'test1', 'version': '1.0.0'}
            },
            {
                'database_specific': {'severity': 'LOW'},
                'affected_package': {'name': 'test2', 'version': '1.0.0'}
            }
        ]
        
        breakdown = self.scanner._get_severity_breakdown(test_vulnerabilities)
        self.assertEqual(breakdown['HIGH'], 1)
        self.assertEqual(breakdown['LOW'], 1)
        self.assertEqual(breakdown['CRITICAL'], 0)


if __name__ == '__main__':
    unittest.main()
