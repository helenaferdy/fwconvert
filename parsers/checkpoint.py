import csv
import io
import re

def parse_checkpoint_csv(content_str):
    """
    Parses a Check Point rulebase CSV export from SmartConsole.
    Typically contains headers like: No., Name, Source, Destination, VPN, Services & Applications, Action, Track, Install On, Time, Comment
    Also handles basic NAT rules if present in standard columns.
    """
    addresses = []
    services = []
    rules = []
    nat_rules = []
    
    # Read CSV content
    f = io.StringIO(content_str.strip())
    reader = csv.reader(f)
    
    headers = []
    rows = []
    
    for row in reader:
        if not row:
            continue
        # Detect header row
        if not headers and any(h in "".join(row).lower() for h in ["source", "destination", "action", "services"]):
            headers = [h.strip().lower() for h in row]
            continue
        if headers:
            rows.append(row)
        else:
            # Fallback if no header row detected yet
            if len(row) > 5:
                rows.append(row)

    # If headers not found, set default based on length
    if not headers and rows:
        max_cols = max(len(r) for r in rows)
        headers = [f"col_{i}" for i in range(max_cols)]
    
    # Map headers to indices
    col_map = {name: idx for idx, name in enumerate(headers)}
    
    def get_val(row, col_names, default=""):
        for name in col_names:
            if name in col_map and col_map[name] < len(row):
                return row[col_map[name]].strip()
        return default

    rule_id_counter = 1
    
    for row in rows:
        # Check if this row is a section title (often single non-empty cell or contains section headers)
        non_empty = [c for c in row if c.strip()]
        if len(non_empty) == 1 and not row[0].strip().isdigit():
            # Section header, skip or log
            continue
            
        no = get_val(row, ["no.", "no", "number", "id"])
        name = get_val(row, ["name", "rule name"])
        src = get_val(row, ["source", "src"])
        dst = get_val(row, ["destination", "dst", "dest"])
        vpn = get_val(row, ["vpn", "vpn community"])
        svc = get_val(row, ["services & applications", "services", "service", "port"])
        action = get_val(row, ["action", "rule action"])
        track = get_val(row, ["track", "logging", "log"])
        comment = get_val(row, ["comment", "comments", "description"])
        
        if not src and not dst and not action:
            continue
            
        # Standardize action
        action_lower = action.lower()
        std_action = "deny"
        if any(a in action_lower for a in ["accept", "allow", "permit", "subpolicy"]):
            std_action = "allow"
            
        # Parse lists
        src_addrs = [s.strip() for s in re.split(r'[,\n;]+', src) if s.strip()]
        dst_addrs = [d.strip() for d in re.split(r'[,\n;]+', dst) if d.strip()]
        services_list = [s.strip() for s in re.split(r'[,\n;]+', svc) if s.strip()]
        
        # Populate address/service objects if they look like specific objects (not 'Any')
        for s in src_addrs:
            if s.lower() != 'any' and s not in [a['name'] for a in addresses]:
                addresses.append({"name": s, "type": "object", "value": "Check Point Object"})
        for d in dst_addrs:
            if d.lower() != 'any' and d not in [a['name'] for a in addresses]:
                addresses.append({"name": d, "type": "object", "value": "Check Point Object"})
        for s_item in services_list:
            if s_item.lower() != 'any' and s_item not in [s_obj['name'] for s_obj in services]:
                services.append({"name": s_item, "protocol": "Any", "port": s_item})
                
        rules.append({
            "id": no or str(rule_id_counter),
            "name": name or f"CP_Rule_{rule_id_counter}",
            "src_zones": ["Any"],
            "dst_zones": ["Any"],
            "src_addrs": src_addrs or ["Any"],
            "dst_addrs": dst_addrs or ["Any"],
            "services": services_list or ["Any"],
            "action": std_action,
            "comment": comment or f"Check Point rule: {name}"
        })
        rule_id_counter += 1

    return {
        "addresses": addresses,
        "services": services,
        "rules": rules,
        "nat": nat_rules
    }
