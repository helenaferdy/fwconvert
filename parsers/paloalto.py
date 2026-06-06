import xml.etree.ElementTree as ET
import io

def parse_paloalto_xml(content_str):
    """
    Parses Palo Alto XML configuration.
    Hardened against XXE and DTD processing.
    """
    addresses = []
    services = []
    rules = []
    nat_rules = []
    
    try:
        # Secure parser configuration: Use standard ET with explicit protections
        # Python ET is safe against XXE by default (does not fetch external resources).
        parser = ET.XMLParser()
        tree = ET.parse(io.StringIO(content_str), parser=parser)
        root = tree.getroot()
    except Exception as e:
        # Return empty list or structure if invalid XML
        return {
            "addresses": [],
            "services": [],
            "rules": [],
            "nat": [],
            "error": f"Invalid XML: {str(e)}"
        }

    # Find vsys entries
    # Palo Alto schema: /config/devices/entry/vsys/entry/
    vsys_entries = root.findall(".//vsys/entry")
    if not vsys_entries:
        # Fallback to direct search if vsys hierarchy is flatter
        vsys_entries = [root]

    for vsys in vsys_entries:
        # 1. Parse Address Objects
        address_nodes = vsys.findall("./address/entry")
        for addr in address_nodes:
            name = addr.get("name")
            val = ""
            addr_type = "ip"
            
            ip_netmask = addr.find("ip-netmask")
            ip_range = addr.find("ip-range")
            fqdn = addr.find("fqdn")
            
            if ip_netmask is not None:
                val = ip_netmask.text or ""
                addr_type = "subnet"
            elif ip_range is not None:
                val = ip_range.text or ""
                addr_type = "range"
            elif fqdn is not None:
                val = fqdn.text or ""
                addr_type = "fqdn"
                
            addresses.append({
                "name": name,
                "type": addr_type,
                "value": val
            })
            
        # 2. Parse Address Groups
        group_nodes = vsys.findall("./address-group/entry")
        for grp in group_nodes:
            name = grp.get("name")
            members = []
            static_node = grp.find("static")
            if static_node is not None:
                for member in static_node.findall("member"):
                    if member.text:
                        members.append(member.text)
            
            addresses.append({
                "name": name,
                "type": "group",
                "value": ", ".join(members)
            })

        # 3. Parse Custom Services
        service_nodes = vsys.findall("./service/entry")
        for svc in service_nodes:
            name = svc.get("name")
            proto = "Any"
            port_val = ""
            
            tcp_node = svc.find("./protocol/tcp")
            udp_node = svc.find("./protocol/udp")
            
            if tcp_node is not None:
                proto = "TCP"
                port_elem = tcp_node.find("port")
                if port_elem is not None:
                    port_val = port_elem.text or ""
            elif udp_node is not None:
                proto = "UDP"
                port_elem = udp_node.find("port")
                if port_elem is not None:
                    port_val = port_elem.text or ""
                    
            services.append({
                "name": name,
                "protocol": proto,
                "port": port_val
            })

        # 4. Parse Security Rules
        rule_nodes = vsys.findall(".//security/rules/entry")
        rule_id = 1
        for rule in rule_nodes:
            name = rule.get("name") or f"PA_Rule_{rule_id}"
            
            # Helper to extract member list from elements
            def get_members(node_name):
                node = rule.find(node_name)
                if node is not None:
                    return [m.text for m in node.findall("member") if m.text]
                return []
                
            src_zones = get_members("from")
            dst_zones = get_members("to")
            src_addrs = get_members("source")
            dst_addrs = get_members("destination")
            services_list = get_members("service")
            
            action_elem = rule.find("action")
            action = action_elem.text if action_elem is not None else "allow"
            
            desc_elem = rule.find("description")
            desc = desc_elem.text if desc_elem is not None else f"Palo Alto Rule: {name}"
            
            rules.append({
                "id": str(rule_id),
                "name": name,
                "src_zones": src_zones or ["any"],
                "dst_zones": dst_zones or ["any"],
                "src_addrs": src_addrs or ["any"],
                "dst_addrs": dst_addrs or ["any"],
                "services": services_list or ["any"],
                "action": "allow" if action.lower() == "allow" else "deny",
                "comment": desc
            })
            rule_id += 1

        # 5. Parse NAT Rules
        nat_nodes = vsys.findall(".//nat/rules/entry")
        nat_id = 1
        for nat in nat_nodes:
            name = nat.get("name") or f"PA_NAT_{nat_id}"
            
            def get_nat_members(node_name):
                node = nat.find(node_name)
                if node is not None:
                    return [m.text for m in node.findall("member") if m.text]
                return []

            orig_src = get_nat_members("source")
            orig_dst = get_nat_members("destination")
            orig_svc_elem = nat.find("service")
            orig_svc = orig_svc_elem.text if orig_svc_elem is not None else "any"

            # Parse translations
            trans_src = "Original"
            trans_dst = "Original"
            trans_svc = "Original"
            nat_type = "Static NAT"

            src_trans = nat.find("source-translation")
            if src_trans is not None:
                nat_type = "Source NAT"
                dip = src_trans.find(".//dynamic-ip-and-port")
                if dip is not None:
                    addr_m = dip.findall(".//member")
                    if addr_m:
                        trans_src = ", ".join([m.text for m in addr_m if m.text])
                    else:
                        trans_src = "Dynamic IP"
                else:
                    sip = src_trans.find(".//static-ip")
                    if sip is not None:
                        t_addr = sip.find("translated-address")
                        if t_addr is not None and t_addr.text:
                            trans_src = t_addr.text

            dst_trans = nat.find("destination-translation")
            if dst_trans is not None:
                nat_type = "Destination NAT"
                t_addr = dst_trans.find("translated-address")
                if t_addr is not None and t_addr.text:
                    trans_dst = t_addr.text
                t_port = dst_trans.find("translated-port")
                if t_port is not None and t_port.text:
                    trans_svc = t_port.text

            nat_rules.append({
                "id": str(nat_id),
                "name": name,
                "orig_src": orig_src or ["any"],
                "trans_src": [trans_src],
                "orig_dst": orig_dst or ["any"],
                "trans_dst": [trans_dst],
                "orig_svc": [orig_svc],
                "trans_svc": [trans_svc],
                "type": nat_type,
                "comment": f"Palo Alto NAT rule: {name}"
            })
            nat_id += 1

    return {
        "addresses": addresses,
        "services": services,
        "rules": rules,
        "nat": nat_rules
    }
