import unittest
from parsers import parse_asa_cli, parse_checkpoint_csv, parse_fortigate_cli, parse_paloalto_xml, parse_ftd_fmc

class TestParsers(unittest.TestCase):
    def test_asa_parser(self):
        config = """
        object network my-host
         host 10.0.0.1
        access-list inside_in extended permit tcp any host 10.0.0.1 eq 80
        """
        res = parse_asa_cli(config)
        self.assertTrue(len(res["addresses"]) > 0)
        self.assertEqual(res["addresses"][0]["name"], "my-host")
        self.assertEqual(res["addresses"][0]["value"], "10.0.0.1")
        self.assertTrue(len(res["rules"]) > 0)
        self.assertEqual(res["rules"][0]["action"], "allow")

    def test_checkpoint_parser(self):
        csv_content = """No.,Name,Source,Destination,Services & Applications,Action,Comment
1,AllowWeb,Any,WebServer,http,Accept,Allow web access
"""
        res = parse_checkpoint_csv(csv_content)
        self.assertTrue(len(res["rules"]) > 0)
        self.assertEqual(res["rules"][0]["name"], "AllowWeb")
        self.assertEqual(res["rules"][0]["action"], "allow")
        self.assertIn("WebServer", res["rules"][0]["dst_addrs"])

    def test_fortigate_parser(self):
        config = """
        config firewall address
            edit "Local-Net"
                set subnet 192.168.1.0 255.255.255.0
            next
        end
        config firewall policy
            edit 10
                set srcintf "port1"
                set dstintf "port2"
                set srcaddr "Local-Net"
                set dstaddr "all"
                set action accept
                set status enable
                set service "HTTP"
            next
        end
        """
        res = parse_fortigate_cli(config)
        self.assertTrue(len(res["addresses"]) > 0)
        self.assertEqual(res["addresses"][0]["name"], "Local-Net")
        self.assertEqual(res["addresses"][0]["value"], "192.168.1.0/255.255.255.0")
        self.assertTrue(len(res["rules"]) > 0)
        self.assertEqual(res["rules"][0]["id"], "10")
        self.assertEqual(res["rules"][0]["action"], "allow")

    def test_paloalto_parser(self):
        xml_content = """<config>
          <devices>
            <entry name="localhost">
              <vsys>
                <entry name="vsys1">
                  <address>
                    <entry name="Office-Net">
                      <ip-netmask>10.1.0.0/16</ip-netmask>
                    </entry>
                  </address>
                  <rulebase>
                    <security>
                      <rules>
                        <entry name="Allow-Office">
                          <from><member>Trust</member></from>
                          <to><member>DMZ</member></to>
                          <source><member>Office-Net</member></source>
                          <destination><member>any</member></destination>
                          <service><member>any</member></service>
                          <action>allow</action>
                        </entry>
                      </rules>
                    </security>
                  </rulebase>
                </entry>
              </vsys>
            </entry>
          </devices>
        </config>
        """
        res = parse_paloalto_xml(xml_content)
        self.assertTrue(len(res["addresses"]) > 0)
        self.assertEqual(res["addresses"][0]["name"], "Office-Net")
        self.assertEqual(res["addresses"][0]["value"], "10.1.0.0/16")
        self.assertTrue(len(res["rules"]) > 0)
        self.assertEqual(res["rules"][0]["name"], "Allow-Office")

    def test_ftd_parser(self):
        json_content = """{
            "items": [
                {
                    "name": "FMC-Allow-Rule",
                    "action": "ALLOW",
                    "sourceNetworks": {"objects": [{"name": "Net_Inside"}]},
                    "destinationNetworks": {"objects": [{"name": "Net_Outside"}]},
                    "destinationPorts": {"objects": [{"name": "HTTP_Port"}]}
                }
            ]
        }"""
        res = parse_ftd_fmc(json_content)
        self.assertTrue(len(res["rules"]) > 0)
        self.assertEqual(res["rules"][0]["name"], "FMC-Allow-Rule")
        self.assertEqual(res["rules"][0]["action"], "allow")

if __name__ == '__main__':
    unittest.main()
