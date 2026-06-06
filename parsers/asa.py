import re

def parse_asa_cli(content_str):
    """
    Parses Cisco ASA show run / configuration script.
    Extracts objects, groups, and access-lists.
    """
    addresses = []
    services = []
    rules = []
    nat_rules = []
    
    lines = content_str.splitlines()
    
    current_obj_name = None
    current_obj_type = None
    current_obj_val = None
    
    current_group_name = None
    current_group_members = []
    
    addr_map = {}
    group_map = {}
    
    for line in lines:
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('!'):
            continue
            
        # Detect single object definition
        if line_stripped.startswith('object network'):
            # Save previous group if any
            if current_group_name:
                group_map[current_group_name] = current_group_members
                addresses.append({
                    "name": current_group_name,
                    "type": "group",
                    "value": ", ".join(current_group_members)
                })
                current_group_name = None
                current_group_members = []
                
            match = re.match(r'object\s+network\s+(\S+)', line_stripped)
            if match:
                current_obj_name = match.group(1)
                current_obj_type = "ip"
                current_obj_val = ""
            continue
            
        # Parse host, subnet, range inside object network
        if current_obj_name:
            if line_stripped.startswith('host'):
                val_match = re.match(r'host\s+(\S+)', line_stripped)
                if val_match:
                    current_obj_val = val_match.group(1)
                    current_obj_type = "host"
            elif line_stripped.startswith('subnet'):
                # subnet 192.168.1.0 255.255.255.0
                subnet_match = re.match(r'subnet\s+([\d\.]+)\s+([\d\.]+)', line_stripped)
                if subnet_match:
                    current_obj_val = f"{subnet_match.group(1)}/{subnet_match.group(2)}"
                    current_obj_type = "subnet"
            elif line_stripped.startswith('range'):
                range_match = re.match(r'range\s+(\S+)\s+(\S+)', line_stripped)
                if range_match:
                    current_obj_val = f"{range_match.group(1)}-{range_match.group(2)}"
                    current_obj_type = "range"
            elif line_stripped.startswith('object') or line_stripped.startswith('object-group') or line_stripped.startswith('access-list'):
                # Ended previous object block
                addresses.append({
                    "name": current_obj_name,
                    "type": current_obj_type,
                    "value": current_obj_val or ""
                })
                addr_map[current_obj_name] = current_obj_val
                current_obj_name = None
                
        # Detect group definition
        if line_stripped.startswith('object-group network'):
            # Save previous group if any
            if current_group_name:
                group_map[current_group_name] = current_group_members
                addresses.append({
                    "name": current_group_name,
                    "type": "group",
                    "value": ", ".join(current_group_members)
                })
                current_group_members = []
                
            match = re.match(r'object-group\s+network\s+(\S+)', line_stripped)
            if match:
                current_group_name = match.group(1)
            continue
            
        if current_group_name:
            if line_stripped.startswith('network-object object'):
                m_match = re.match(r'network-object\s+object\s+(\S+)', line_stripped)
                if m_match:
                    current_group_members.append(m_match.group(1))
            elif line_stripped.startswith('network-object host'):
                m_match = re.match(r'network-object\s+host\s+(\S+)', line_stripped)
                if m_match:
                    current_group_members.append(m_match.group(1))
            elif line_stripped.startswith('network-object'):
                # e.g. network-object 192.168.1.0 255.255.255.0
                m_match = re.match(r'network-object\s+([\d\.]+)\s+([\d\.]+)', line_stripped)
                if m_match:
                    current_group_members.append(f"{m_match.group(1)}/{m_match.group(2)}")
            elif line_stripped.startswith('object') or line_stripped.startswith('object-group') or line_stripped.startswith('access-list'):
                group_map[current_group_name] = current_group_members
                addresses.append({
                    "name": current_group_name,
                    "type": "group",
                    "value": ", ".join(current_group_members)
                })
                current_group_name = None
                current_group_members = []

    # Final sweep to catch last active objects/groups
    if current_obj_name:
        addresses.append({"name": current_obj_name, "type": current_obj_type, "value": current_obj_val or ""})
        addr_map[current_obj_name] = current_obj_val
    if current_group_name:
        group_map[current_group_name] = current_group_members
        addresses.append({"name": current_group_name, "type": "group", "value": ", ".join(current_group_members)})

    # Now parse Access Lists
    # access-list <name> extended <permit/deny> <protocol> <source> <destination> [service]
    # e.g. access-list inside_in extended permit ip object my-subnet host 10.0.0.1
    # e.g. access-list inside_in extended permit tcp any any eq 80
    acl_count = 1
    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith('access-list'):
            # Standardize spacing
            parts = re.split(r'\s+', line_stripped)
            if len(parts) < 6:
                continue
                
            acl_name = parts[1]
            # extended permit/deny protocol source ...
            action_idx = 3 if parts[2] == 'extended' else 2
            
            if action_idx >= len(parts):
                continue
                
            action = parts[action_idx]
            protocol = parts[action_idx + 1]
            
            # Extract source
            src_start = action_idx + 2
            if src_start >= len(parts):
                continue
                
            src_addrs = []
            if parts[src_start] == 'object':
                src_addrs.append(parts[src_start + 1])
                dst_start = src_start + 2
            elif parts[src_start] == 'host':
                src_addrs.append(parts[src_start + 1])
                dst_start = src_start + 2
            elif parts[src_start] == 'any':
                src_addrs.append('any')
                dst_start = src_start + 1
            else:
                # E.g. network IP mask
                if src_start + 1 < len(parts) and re.match(r'[\d\.]+', parts[src_start]):
                    src_addrs.append(f"{parts[src_start]}/{parts[src_start+1]}")
                    dst_start = src_start + 2
                else:
                    src_addrs.append(parts[src_start])
                    dst_start = src_start + 1
                    
            # Extract destination
            if dst_start >= len(parts):
                continue
                
            dst_addrs = []
            if parts[dst_start] == 'object':
                dst_addrs.append(parts[dst_start + 1])
                svc_start = dst_start + 2
            elif parts[dst_start] == 'host':
                dst_addrs.append(parts[dst_start + 1])
                svc_start = dst_start + 2
            elif parts[dst_start] == 'any':
                dst_addrs.append('any')
                svc_start = dst_start + 1
            else:
                if dst_start + 1 < len(parts) and re.match(r'[\d\.]+', parts[dst_start]):
                    dst_addrs.append(f"{parts[dst_start]}/{parts[dst_start+1]}")
                    svc_start = dst_start + 2
                else:
                    dst_addrs.append(parts[dst_start])
                    svc_start = dst_start + 1
                    
            # Extract service/port
            services_list = []
            if svc_start < len(parts):
                if parts[svc_start] == 'eq':
                    services_list.append(f"{protocol}/{parts[svc_start + 1]}")
                elif parts[svc_start] == 'range':
                    services_list.append(f"{protocol}/{parts[svc_start+1]}-{parts[svc_start+2]}")
                elif parts[svc_start] == 'object':
                    services_list.append(parts[svc_start + 1])
                else:
                    services_list.append(protocol)
            else:
                services_list.append(protocol)
                
            rules.append({
                "id": str(acl_count),
                "name": acl_name,
                "src_zones": [acl_name.split('_')[0] if '_' in acl_name else "Any"],
                "dst_zones": ["Any"],
                "src_addrs": src_addrs,
                "dst_addrs": dst_addrs,
                "services": services_list,
                "action": "allow" if action.lower() in ['permit', 'allow'] else "deny",
                "comment": f"Cisco ASA ACL entry: {line_stripped}"
            })
            acl_count += 1
            
    # Parse ASA NAT rules
    nat_count = 1
    for line in lines:
        line_stripped = line.strip()
        if line_stripped.startswith('nat '):
            # Parse dynamic source NAT: nat (inside,outside) source dynamic my-source interface
            m_dyn = re.match(r'nat\s+\((\S+),(\S+)\)\s+source\s+dynamic\s+(\S+)\s+(\S+)', line_stripped)
            if m_dyn:
                nat_rules.append({
                    "id": str(nat_count),
                    "name": f"ASA_NAT_{nat_count}",
                    "orig_src": [m_dyn.group(3)],
                    "trans_src": [m_dyn.group(4)],
                    "orig_dst": ["any"],
                    "trans_dst": ["Original"],
                    "orig_svc": ["any"],
                    "trans_svc": ["Original"],
                    "type": "Source NAT (Dynamic)",
                    "comment": f"Cisco ASA NAT: {line_stripped}"
                })
                nat_count += 1
                continue
            
            # Parse static NAT: nat (inside,outside) source static my-source my-translated-source
            m_stat = re.match(r'nat\s+\((\S+),(\S+)\)\s+source\s+static\s+(\S+)\s+(\S+)', line_stripped)
            if m_stat:
                nat_rules.append({
                    "id": str(nat_count),
                    "name": f"ASA_NAT_{nat_count}",
                    "orig_src": [m_stat.group(3)],
                    "trans_src": [m_stat.group(4)],
                    "orig_dst": ["any"],
                    "trans_dst": ["Original"],
                    "orig_svc": ["any"],
                    "trans_svc": ["Original"],
                    "type": "Static NAT",
                    "comment": f"Cisco ASA NAT: {line_stripped}"
                })
                nat_count += 1
                
    return {
        "addresses": addresses,
        "services": services,
        "rules": rules,
        "nat": nat_rules
    }
