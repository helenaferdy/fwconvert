# FW Convert - Firewall Configuration Converter

A Flask web application that accepts firewall configuration files via upload and parses them into structured JSON. Supports Cisco ASA, Check Point, FortiGate, Palo Alto, and Cisco FTD/FMC platforms. Useful for migrating or auditing firewall rulebases across vendors.

## Supported Platforms
- Cisco ASA
- Check Point
- FortiGate
- Palo Alto
- Cisco FTD/FMC

## Setup
```bash
pip install -r requirements.txt
python app.py
```