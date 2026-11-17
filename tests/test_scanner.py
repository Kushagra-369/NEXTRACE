
import unittest

from nextrace.scanner import parse_scan_results
from nextrace.scanner import parse_host_info

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

    
    def test_parse_host_metadata(self):
        xml_data = """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="127.0.0.1" addrtype="ipv4"/>
            <hostnames>
              <hostname name="localhost" type="PTR"/>
            </hostnames>
            <os>
              <osmatch name="Linux" accuracy="98"/>
            </os>
          </host>
        </nmaprun>
        """

        hosts = parse_host_info(xml_data)

        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["status"], "up")
        self.assertEqual(hosts[0]["hostnames"], ["localhost"])
        self.assertEqual(hosts[0]["os_guesses"][0]["name"], "Linux")

    def test_parse_host_without_optional_fields(self):
        xml_data = """
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="127.0.0.1" addrtype="ipv4"/>
          </host>
        </nmaprun>
        """

        hosts = parse_host_info(xml_data)

        self.assertEqual(hosts[0]["status"], "up")
        self.assertEqual(hosts[0]["hostnames"], [])
        self.assertEqual(hosts[0]["os_guesses"], [])



if __name__ == "__main__":
    unittest.main()
