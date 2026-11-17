
import unittest

from nextrace.discovery import validate_target


class TestTargetValidation(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertTrue(validate_target("127.0.0.1"))

    def test_valid_ipv6(self):
        self.assertTrue(validate_target("::1"))

    def test_valid_hostname(self):
        self.assertTrue(validate_target("example.com"))

    def test_reject_url(self):
        self.assertFalse(validate_target("https://example.com"))

    def test_reject_invalid_ip(self):
        self.assertFalse(validate_target("999.999.999.999"))

    def test_reject_empty_target(self):
        self.assertFalse(validate_target(""))

    def test_reject_hostname_with_spaces(self):
        self.assertFalse(validate_target("example .com"))


if __name__ == "__main__":
    unittest.main()
