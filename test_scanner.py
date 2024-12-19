import unittest
from utils.scanners import check_xss, check_sql_injection

class TestScanner(unittest.TestCase):

    def test_check_xss(self):
        result = check_xss('example.com')
        self.assertIn("Possible XSS vulnerability found", result)

    def test_check_sql_injection(self):
        result = check_sql_injection('example.com')
        self.assertIn("Possible SQL Injection vulnerability found", result)

if __name__ == "__main__":
    unittest.main()
