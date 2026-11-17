
import unittest

from nextrace.scanner import parse_scan_results


SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="5432">
        <state state="open"/>
        <service name="postgresql"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class TestNmapParser(unittest.TestCase):

    def test_parse_open_port(self):
        results = parse_scan_results(SAMPLE_XML)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["host"], "127.0.0.1")
        self.assertEqual(results[0]["port"], 5432)
        self.assertEqual(results[0]["state"], "open")
        self.assertEqual(results[0]["service"], "postgresql")

    def test_empty_scan(self):
        results = parse_scan_results("<nmaprun></nmaprun>")
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
