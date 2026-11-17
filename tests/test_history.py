
import unittest

from nextrace.history import compare_scans


class TestScanComparison(unittest.TestCase):

    def make_port(self, port, state="open", service="http", version="1.0"):
        return {
            "host": "127.0.0.1",
            "protocol": "tcp",
            "port": port,
            "state": state,
            "service": service,
            "product": service,
            "version": version,
        }

    def test_newly_opened_port(self):
        previous = {"ports": []}
        current = {"ports": [self.make_port(8080)]}

        changes = compare_scans(previous, current)

        self.assertEqual(len(changes["newly_opened"]), 1)

    def test_closed_port(self):
        previous = {"ports": [self.make_port(8080)]}
        current = {"ports": [self.make_port(8080, state="closed")]}

        changes = compare_scans(previous, current)

        self.assertEqual(len(changes["closed"]), 1)

    def test_service_version_changed(self):
        previous = {"ports": [self.make_port(8080, version="1.0")]}
        current = {"ports": [self.make_port(8080, version="2.0")]}

        changes = compare_scans(previous, current)

        self.assertEqual(len(changes["service_changed"]), 1)

    def test_missing_port_is_not_assumed_closed(self):
        previous = {"ports": [self.make_port(8080)]}
        current = {"ports": []}

        changes = compare_scans(previous, current)

        self.assertEqual(len(changes["closed"]), 0)
        self.assertEqual(len(changes["no_longer_observed"]), 1)

    def test_unchanged_scan(self):
        port = self.make_port(8080)
        previous = {"ports": [port]}
        current = {"ports": [port.copy()]}

        changes = compare_scans(previous, current)

        self.assertEqual(len(changes["newly_opened"]), 0)
        self.assertEqual(len(changes["closed"]), 0)
        self.assertEqual(len(changes["service_changed"]), 0)
        self.assertEqual(len(changes["no_longer_observed"]), 0)


if __name__ == "__main__":
    unittest.main()
