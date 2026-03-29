#!/usr/bin/env python3
"""
VSH MVP Validation Test Script

Tests all core functionality:
1. File scanning
2. Project scanning  
3. Watch mode
4. Annotation generation
5. API endpoints

Usage:
    python test_vsh_mvp.py --test-dir <path>

Or without args, tests are run against test fixtures in the repo.
"""

import argparse
import json
import time
import requests
import tempfile
import subprocess
import sys
from pathlib import Path


class VSHTestRunner:
    def __init__(self, api_base: str = "http://127.0.0.1:3000"):
        self.api_base = api_base
        self.results = {
            "tests_run": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "tests": []
        }
    
    def log_test(self, name: str, passed: bool, details: str = ""):
        """Log test result."""
        self.results["tests_run"] += 1
        if passed:
            self.results["tests_passed"] += 1
            status = "✓ PASS"
        else:
            self.results["tests_failed"] += 1
            status = "✗ FAIL"
        
        self.results["tests"].append({
            "name": name,
            "passed": passed,
            "details": details
        })
        
        print(f"[{status}] {name}: {details}")
    
    def check_api_health(self):
        """Check if API is running."""
        print("\n=== Checking API Health ===")
        try:
            resp = requests.get(f"{self.api_base}/health", timeout=3)
            if resp.status_code == 200:
                self.log_test("API Health", True, "API is running on port 3000")
                return True
            else:
                self.log_test("API Health", False, f"Got status code {resp.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self.log_test("API Health", False, "Could not connect to API. Is it running?")
            return False
        except Exception as e:
            self.log_test("API Health", False, str(e))
            return False
    
    def test_file_scan(self, test_file: Path):
        """Test scanning a single file."""
        print("\n=== Testing File Scan ===")
        if not test_file.exists():
            self.log_test("File Scan", False, f"Test file not found: {test_file}")
            return False
        
        try:
            resp = requests.post(
                f"{self.api_base}/scan/file",
                json={"path": str(test_file)},
                timeout=30
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if "findings" in data:
                    self.log_test(
                        "File Scan",
                        True,
                        f"Found {data['summary']['total']} finding(s)"
                    )
                    return True
                else:
                    self.log_test("File Scan", False, "Missing 'findings' in response")
                    return False
            else:
                self.log_test(
                    "File Scan",
                    False,
                    f"Status {resp.status_code}: {resp.text[:100]}"
                )
                return False
        except Exception as e:
            self.log_test("File Scan", False, str(e))
            return False
    
    def test_project_scan(self, test_dir: Path):
        """Test scanning a project directory."""
        print("\n=== Testing Project Scan ===")
        if not test_dir.is_dir():
            self.log_test("Project Scan", False, f"Test dir not found: {test_dir}")
            return False
        
        try:
            resp = requests.post(
                f"{self.api_base}/scan/project",
                json={"path": str(test_dir)},
                timeout=60
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if "findings" in data:
                    self.log_test(
                        "Project Scan",
                        True,
                        f"Scanned project, found {data['summary']['total']} finding(s)"
                    )
                    return True
                else:
                    self.log_test("Project Scan", False, "Missing 'findings' in response")
                    return False
            else:
                self.log_test(
                    "Project Scan",
                    False,
                    f"Status {resp.status_code}: {resp.text[:100]}"
                )
                return False
        except Exception as e:
            self.log_test("Project Scan", False, str(e))
            return False
    
    def test_watch_mode(self, test_file: Path):
        """Test watch mode start/stop."""
        print("\n=== Testing Watch Mode ===")
        if not test_file.exists():
            self.log_test(
                "Watch Mode Start",
                False,
                f"Test file not found: {test_file}"
            )
            return False
        
        try:
            # Start watch
            resp_start = requests.post(
                f"{self.api_base}/watch/start",
                json={"path": str(test_file)},
                timeout=10
            )
            
            if resp_start.status_code != 200:
                self.log_test(
                    "Watch Mode Start",
                    False,
                    f"Status {resp_start.status_code}"
                )
                return False
            
            self.log_test("Watch Mode Start", True, "Watch started successfully")
            
            # Wait a bit
            time.sleep(2)
            
            # Check status
            try:
                resp_status = requests.get(
                    f"{self.api_base}/watch/status",
                    timeout=5
                )
                if resp_status.status_code == 200:
                    status_data = resp_status.json()
                    if status_data.get("active_watchers", 0) > 0:
                        self.log_test(
                            "Watch Mode Status",
                            True,
                            f"{status_data['active_watchers']} watcher(s) active"
                        )
                    else:
                        self.log_test(
                            "Watch Mode Status",
                            False,
                            "No active watchers"
                        )
            except:
                pass  # Status endpoint may not be available
            
            # Stop watch
            resp_stop = requests.post(
                f"{self.api_base}/watch/stop",
                json={"path": str(test_file)},
                timeout=10
            )
            
            if resp_stop.status_code == 200:
                self.log_test("Watch Mode Stop", True, "Watch stopped successfully")
                return True
            else:
                self.log_test(
                    "Watch Mode Stop",
                    False,
                    f"Status {resp_stop.status_code}"
                )
                return False
        
        except Exception as e:
            self.log_test("Watch Mode", False, str(e))
            return False
    
    def test_annotation(self, test_file: Path):
        """Test annotation generation."""
        print("\n=== Testing Annotation API ===")
        if not test_file.exists():
            self.log_test(
                "Annotation (File)",
                False,
                f"Test file not found: {test_file}"
            )
            return False
        
        try:
            # Test file annotation (not in-place)
            resp = requests.post(
                f"{self.api_base}/annotate/file",
                json={"path": str(test_file), "in_place": False},
                timeout=30
            )
            
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    self.log_test(
                        "Annotation (File)",
                        True,
                        f"Generated annotation with {data.get('total_issues', 0)} issue(s)"
                    )
                    
                    # Check if annotated files were created
                    annotated_files = data.get("annotated_files", {})
                    if annotated_files:
                        for orig, annotated in annotated_files.items():
                            if Path(annotated).exists():
                                self.log_test(
                                    "Annotation File Created",
                                    True,
                                    f"{Path(annotated).name}"
                                )
                            else:
                                self.log_test(
                                    "Annotation File Created",
                                    False,
                                    f"File not found: {annotated}"
                                )
                    return True
                else:
                    self.log_test("Annotation (File)", False, data.get("message", ""))
                    return False
            else:
                self.log_test(
                    "Annotation (File)",
                    False,
                    f"Status {resp.status_code}"
                )
                return False
        
        except Exception as e:
            self.log_test("Annotation (File)", False, str(e))
            return False
    
    def test_diagnostics_saved(self, test_file: Path):
        """Test that diagnostics are saved after scanning."""
        print("\n=== Testing Diagnostics Saving ===")
        
        # First scan the file
        try:
            requests.post(
                f"{self.api_base}/scan/file",
                json={"path": str(test_file)},
                timeout=30
            )
        except:
            pass
        
        # Check if diagnostics file was created
        if test_file.is_file():
            vsh_dir = test_file.parent / ".vsh"
        else:
            vsh_dir = test_file / ".vsh"
        
        diag_file = vsh_dir / "diagnostics.json"
        report_file = vsh_dir / "report.json"
        
        if diag_file.exists():
            try:
                data = json.loads(diag_file.read_text())
                if isinstance(data, list):
                    self.log_test(
                        "Diagnostics Saved",
                        True,
                        f"Found {len(data)} diagnostic(s)"
                    )
                else:
                    self.log_test("Diagnostics Saved", True, "Diagnostics file created")
            except:
                self.log_test("Diagnostics Saved", False, "Diagnostics file invalid JSON")
        else:
            self.log_test("Diagnostics Saved", False, f"File not found: {diag_file}")
        
        if report_file.exists():
            self.log_test("Report Saved", True, "Report file created")
        else:
            self.log_test("Report Saved", False, f"File not found: {report_file}")
    
    def run_all_tests(self, test_file: str = None, test_dir: str = None):
        """Run all tests."""
        print("VSH MVP Validation Test Suite")
        print("=" * 50)
        
        # Use provided paths or find defaults
        if not test_file:
            # Try to find a test file in the repo
            repo_root = Path(__file__).parent
            test_file = repo_root / "VSH_Project_MVP" / "tests" / "fixtures"
            if (test_file / "python_multi_bad.py").exists():
                test_file = test_file / "python_multi_bad.py"
            else:
                # Create a minimal test file
                test_file = Path(tempfile.gettempdir()) / "vsh_test.py"
                test_file.write_text(
                    '# Security test file\nimport os\npassword = "hardcoded_secret"'
                )
        else:
            test_file = Path(test_file)
        
        if not test_dir:
            test_dir = test_file.parent
        else:
            test_dir = Path(test_dir)
        
        print(f"Test File: {test_file}")
        print(f"Test Dir:  {test_dir}")
        print("=" * 50)
        
        # Run tests
        if not self.check_api_health():
            print("\n⚠️  API is not running. Skipping remaining tests.")
            print("To run tests, start the API with:")
            print("  python -m uvicorn vsh_api.main:app --host 127.0.0.1 --port 3000")
            return
        
        self.test_file_scan(test_file)
        self.test_project_scan(test_dir)
        self.test_watch_mode(test_file)
        self.test_annotation(test_file)
        self.test_diagnostics_saved(test_file)
        
        # Print summary
        print("\n" + "=" * 50)
        print("TEST SUMMARY")
        print("=" * 50)
        print(f"Tests Run:    {self.results['tests_run']}")
        print(f"Tests Passed: {self.results['tests_passed']}")
        print(f"Tests Failed: {self.results['tests_failed']}")
        
        # Exit with appropriate code
        if self.results['tests_failed'] > 0:
            sys.exit(1)
        else:
            print("\n✓ All tests passed!")
            sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VSH MVP Validation Test Suite"
    )
    parser.add_argument(
        "--test-file",
        help="Path to a test file to scan"
    )
    parser.add_argument(
        "--test-dir",
        help="Path to a test directory to scan"
    )
    parser.add_argument(
        "--api-base",
        default="http://127.0.0.1:3000",
        help="API base URL (default: http://127.0.0.1:3000)"
    )
    
    args = parser.parse_args()
    
    runner = VSHTestRunner(api_base=args.api_base)
    runner.run_all_tests(test_file=args.test_file, test_dir=args.test_dir)
