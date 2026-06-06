import json
import csv
import io
import re

def parse_ftd_fmc(content_str):
    """
    Parses Cisco FTD (Firepower Threat Defense) access control policies exported from FMC.
    Supports either standard FMC JSON export or FMC policy grid CSV export.
    """
    addresses = []
    services = []
    rules = []
    nat_rules = []
    
    # Try parsing as JSON first
    try:
        data = json.loads(content_str)
        if isinstance(data, dict):
            # FMC policy export formats often contain 'items' or 'rules'
            items = data.get("items") or data.get("rules") or []
            if not items and "metadata" in data:
                # Flat format or different nesting
                items = [data]
            
            if items:
                rule_id = 1
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name") or f"FTD_Rule_{rule_id}"
                    action = item.get("action") or "ALLOW"
                    
                    # Resolve helper for networks/ports objects
                    def extract_fmc_objects(obj_field):
                        objects = []
                        if not obj_field:
                            return objects
                        if isinstance(obj_field, dict):
                            # e.g. {"objects": [{"name": "net1"}], "literals": [{"value": "10.0.0.1"}]}
                            for obj in obj_field.get("objects", []):
                                if "name" in obj:
                                    objects.append(obj["name"])
                            for lit in obj_field.get("literals", []):
                                if "value" in lit:
                                    objects.append(lit["value"])
                        elif isinstance(obj_field, list):
                            for obj in obj_field:
                                if isinstance(obj, dict):
                                    objects.append(obj.get("name") or obj.get("value") or "")
                                elif isinstance(obj, str):
                                    objects.append(obj)
                        return [o for o in objects if o]

                    src_addrs = extract_fmc_objects(item.get("sourceNetworks"))
                    dst_addrs = extract_fmc_objects(item.get("destinationNetworks"))
                    src_zones = extract_fmc_objects(item.get("sourceZones"))
                    dst_zones = extract_fmc_objects(item.get("destinationZones"))
                    services_list = extract_fmc_objects(item.get("destinationPorts"))
                    
                    # Save addresses/services
                    for s in src_addrs:
                        if s.lower() != 'any' and s not in [a['name'] for a in addresses]:
                            addresses.append({"name": s, "type": "object", "value": "FMC Object"})
                    for d in dst_addrs:
                        if d.lower() != 'any' and d not in [a['name'] for a in addresses]:
                            addresses.append({"name": d, "type": "object", "value": "FMC Object"})
                    for s_item in services_list:
                        if s_item.lower() != 'any' and s_item not in [s_obj['name'] for s_obj in services]:
                            services.append({"name": s_item, "protocol": "Any", "port": s_item})
                            
                    rules.append({
                        "id": str(rule_id),
                        "name": name,
                        "src_zones": src_zones or ["any"],
                        "dst_zones": dst_zones or ["any"],
                        "src_addrs": src_addrs or ["any"],
                        "dst_addrs": dst_addrs or ["any"],
                        "services": services_list or ["any"],
                        "action": "allow" if action.upper() in ["ALLOW", "PERMIT"] else "deny",
                        "comment": item.get("description") or f"FMC Rule: {name}"
                    })
                    rule_id += 1
            
            # Parse FMC NAT rules if they are present in the JSON
            nat_items = data.get("nat") or data.get("nat_rules") or []
            if isinstance(nat_items, list):
                nat_id = 1
                for item in nat_items:
                    if not isinstance(item, dict):
                        continue
                    name = item.get("name") or f"FTD_NAT_{nat_id}"
                    nat_type = item.get("type") or item.get("natType") or "Static NAT"
                    
                    def extract_names(field):
                        if not field:
                            return ["any"]
                        if isinstance(field, list):
                            return field
                        if isinstance(field, dict):
                            if "name" in field:
                                return [field["name"]]
                            if "objects" in field:
                                return [o.get("name") for o in field.get("objects", []) if "name" in o]
                        return [str(field)]

                    orig_src = extract_names(item.get("originalSource") or item.get("orig_src"))
                    trans_src = extract_names(item.get("translatedSource") or item.get("trans_src"))
                    orig_dst = extract_names(item.get("originalDestination") or item.get("orig_dst"))
                    trans_dst = extract_names(item.get("translatedDestination") or item.get("trans_dst"))
                    orig_svc = extract_names(item.get("originalService") or item.get("orig_svc"))
                    trans_svc = extract_names(item.get("translatedService") or item.get("trans_svc"))

                    nat_rules.append({
                        "id": str(nat_id),
                        "name": name,
                        "orig_src": orig_src,
                        "trans_src": trans_src,
                        "orig_dst": orig_dst,
                        "trans_dst": trans_dst,
                        "orig_svc": orig_svc,
                        "trans_svc": trans_svc,
                        "type": nat_type,
                        "comment": item.get("description") or f"FTD NAT Rule: {name}"
                    })
                    nat_id += 1
                    
                return {
                    "addresses": addresses,
                    "services": services,
                    "rules": rules,
                    "nat": nat_rules
                }
    except Exception:
        # Fallback to CSV parser if not JSON
        pass

    # CSV Parser for FMC export
    f = io.StringIO(content_str.strip())
    reader = csv.reader(f)
    headers = []
    rows = []
    
    for row in reader:
        if not row:
            continue
        if not headers and any(h in "".join(row).lower() for h in ["source network", "destination network", "action", "rule"]):
            headers = [h.strip().lower() for h in row]
            continue
        if headers:
            rows.append(row)
            
    if not headers and rows:
        max_cols = max(len(r) for r in rows)
        headers = [f"col_{i}" for i in range(max_cols)]
        
    col_map = {name: idx for idx, name in enumerate(headers)}
    
    def get_val(row, col_names, default=""):
        for name in col_names:
            if name in col_map and col_map[name] < len(row):
                return row[col_map[name]].strip()
        return default

    rule_id = 1
    for row in rows:
        name = get_val(row, ["name", "rule", "rule name"])
        src_net = get_val(row, ["source networks", "source network", "src net"])
        dst_net = get_val(row, ["destination networks", "destination network", "dst net"])
        src_zone = get_val(row, ["source zones", "source zone", "src zone"])
        dst_zone = get_val(row, ["destination zones", "destination zone", "dst zone"])
        ports = get_val(row, ["destination ports", "ports", "port", "services"])
        action = get_val(row, ["action"])
        comment = get_val(row, ["comment", "description"])
        
        if not name and not action:
            continue
            
        src_addrs = [s.strip() for s in re.split(r'[,\n;]+', src_net) if s.strip()]
        dst_addrs = [d.strip() for d in re.split(r'[,\n;]+', dst_net) if d.strip()]
        src_zones = [z.strip() for z in re.split(r'[,\n;]+', src_zone) if z.strip()]
        dst_zones = [z.strip() for z in re.split(r'[,\n;]+', dst_zone) if z.strip()]
        services_list = [p.strip() for p in re.split(r'[,\n;]+', ports) if p.strip()]
        
        # Populate address/service objects
        for s in src_addrs:
            if s.lower() != 'any' and s not in [a['name'] for a in addresses]:
                addresses.append({"name": s, "type": "object", "value": "FMC Object"})
        for d in dst_addrs:
            if d.lower() != 'any' and d not in [a['name'] for a in addresses]:
                addresses.append({"name": d, "type": "object", "value": "FMC Object"})
        for s_item in services_list:
            if s_item.lower() != 'any' and s_item not in [s_obj['name'] for s_obj in services]:
                services.append({"name": s_item, "protocol": "Any", "port": s_item})
                
        rules.append({
            "id": str(rule_id),
            "name": name or f"FTD_Rule_{rule_id}",
            "src_zones": src_zones or ["any"],
            "dst_zones": dst_zones or ["any"],
            "src_addrs": src_addrs or ["any"],
            "dst_addrs": dst_addrs or ["any"],
            "services": services_list or ["any"],
            "action": "allow" if action.lower() in ["allow", "permit"] else "deny",
            "comment": comment or f"FTD FMC Rule: {name}"
        })
        rule_id += 1

    return {
        "addresses": addresses,
        "services": services,
        "rules": rules,
        "nat": nat_rules
    }
