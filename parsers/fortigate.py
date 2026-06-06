import re

def parse_fortigate_cli(content_str):
    """
    Parses FortiGate CLI configuration scripts.
    Extracts address objects, address groups, custom services, and security policies.
    """
    addresses = []
    services = []
    rules = []
    nat_rules = []
    
    addr_map = {}
    group_map = {}
    
    lines = content_str.splitlines()
    
    current_block = None
    current_item = {}
    
    # Simple block parser state machine
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            continue
            
        # Detect start of configuration sections
        if line_stripped.startswith('config firewall address'):
            current_block = 'address'
            continue
        elif line_stripped.startswith('config firewall addrgrp'):
            current_block = 'addrgrp'
            continue
        elif line_stripped.startswith('config firewall service custom'):
            current_block = 'service'
            continue
        elif line_stripped.startswith('config firewall policy'):
            current_block = 'policy'
            continue
        elif line_stripped == 'end':
            # Close block
            current_block = None
            continue
            
        if current_block:
            # Inside a block
            if line_stripped.startswith('edit'):
                # Start new item definition
                match = re.match(r'edit\s+"?([^"\s]+)"?', line_stripped)
                if match:
                    current_item = {"name": match.group(1)}
            elif line_stripped.startswith('next'):
                # End of current item definition, save it
                if "name" in current_item:
                    if current_block == 'address':
                        addr_type = "ip"
                        val = current_item.get("subnet") or current_item.get("iprange") or current_item.get("fqdn") or ""
                        if current_item.get("subnet"):
                            addr_type = "subnet"
                        elif current_item.get("iprange"):
                            addr_type = "range"
                        elif current_item.get("fqdn"):
                            addr_type = "fqdn"
                            
                        addresses.append({
                            "name": current_item["name"],
                            "type": addr_type,
                            "value": val
                        })
                        addr_map[current_item["name"]] = val
                    elif current_block == 'addrgrp':
                        members = current_item.get("members", [])
                        addresses.append({
                            "name": current_item["name"],
                            "type": "group",
                            "value": ", ".join(members)
                        })
                        group_map[current_item["name"]] = members
                    elif current_block == 'service':
                        proto = current_item.get("protocol", "TCP/UDP")
                        port = current_item.get("tcp-portrange") or current_item.get("udp-portrange") or ""
                        services.append({
                            "name": current_item["name"],
                            "protocol": proto,
                            "port": port
                        })
                    elif current_block == 'policy':
                        action = current_item.get("action", "deny")
                        status = current_item.get("status", "enable")
                        
                        rules.append({
                            "id": current_item["name"],
                            "name": current_item.get("comments") or f"Policy_{current_item['name']}",
                            "src_zones": current_item.get("srcintf", ["any"]),
                            "dst_zones": current_item.get("dstintf", ["any"]),
                            "src_addrs": current_item.get("srcaddr", ["all"]),
                            "dst_addrs": current_item.get("dstaddr", ["all"]),
                            "services": current_item.get("service", ["ALL"]),
                            "action": "allow" if action.lower() in ["accept", "permit"] else "deny",
                            "comment": current_item.get("comments") or f"FortiGate Policy ID: {current_item['name']}"
                        })
                current_item = {}
            else:
                # Parsing parameters inside an item
                if line_stripped.startswith('set '):
                    parts = re.split(r'\s+', line_stripped[4:])
                    if len(parts) >= 2:
                        param = parts[0]
                        # Join the rest, stripping quotes helper
                        def clean_list(val_parts):
                            val_str = " ".join(val_parts)
                            # find all double quoted strings or unquoted words
                            return [v.strip('"') for v in re.findall(r'"[^"]*"|\S+', val_str)]
                            
                        val_list = clean_list(parts[1:])
                        
                        if param == 'subnet':
                            # subnet 192.168.1.0 255.255.255.0
                            if len(val_list) == 2:
                                current_item['subnet'] = f"{val_list[0]}/{val_list[1]}"
                            else:
                                current_item['subnet'] = " ".join(val_list)
                        elif param == 'iprange':
                            current_item['iprange'] = "-".join(val_list)
                        elif param == 'fqdn':
                            current_item['fqdn'] = val_list[0]
                        elif param == 'member':
                            current_item['members'] = val_list
                        elif param in ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service']:
                            current_item[param] = val_list
                        elif param in ['action', 'status', 'comments']:
                            current_item[param] = " ".join(val_list)
                        elif param in ['tcp-portrange', 'udp-portrange']:
                            current_item[param] = " ".join(val_list)

    return {
        "addresses": addresses,
        "services": services,
        "rules": rules,
        "nat": nat_rules
    }
