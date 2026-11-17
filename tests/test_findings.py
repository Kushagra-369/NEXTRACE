
import unittest

from nextrace.findings import generate_findings


class TestFindings(unittest.TestCase):

    def make_result(self, host, service, state="open", port=80):
        return {
            "host": host,
            "port": port,
            "service": service,
            "state": state,
        }

    def test_loopback_database_is_not_flagged_as_exposed(self):
        results = [
            self.make_result("127.0.0.1", "postgresql", port=5432)
        ]

        findings = generate_findings(results)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["severity"], "informational"
        )
        self.assertEqual(
            findings[0]["id"], "open_service_observed"
        )

    def test_network_exposed_database(self):
        results = [
            self.make_result("192.168.1.10", "postgresql", port=5432)
        ]

        findings = generate_findings(results)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["id"], "network_exposed_database"
        )
        self.assertEqual(findings[0]["severity"], "medium")

    def test_plaintext_protocol(self):
        results = [
            self.make_result("127.0.0.1", "ftp", port=21)
        ]

        findings = generate_findings(results)

        self.assertEqual(findings[0]["id"], "plaintext_protocol")
        self.assertEqual(findings[0]["severity"], "medium")

    def test_http_on_non_loopback(self):
        results = [
            self.make_result("192.168.1.10", "http", port=80)
        ]

        findings = generate_findings(results)

        self.assertEqual(findings[0]["id"], "unencrypted_http")
        self.assertEqual(findings[0]["severity"], "low")

    def test_closed_port_is_ignored(self):
        results = [
            self.make_result(
                "192.168.1.10", "postgresql",
                state="closed", port=5432
            )
        ]

        findings = generate_findings(results)

        self.assertEqual(findings, [])

    def test_unknown_service_is_informational(self):
        results = [
            self.make_result(
                "192.168.1.10", "unknown", port=9999
            )
        ]

        findings = generate_findings(results)

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["severity"], "informational"
        )


if __name__ == "__main__":
    unittest.main()
