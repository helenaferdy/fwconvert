import os
import logging
from flask import Flask, render_template, request, jsonify
from parsers import parse_asa_cli, parse_checkpoint_csv, parse_fortigate_cli, parse_paloalto_xml, parse_ftd_fmc

app = Flask(__name__)

# Configure logging securely
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fwconvert")

# Enforce file size limit of 10MB
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/parse', methods=['POST'])
def parse_config():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files['file']
    fw_type = request.form.get('type')
    
    if not file or not fw_type:
        return jsonify({"error": "Missing file or firewall brand type"}), 400
        
    try:
        # Read content fully in-memory to prevent path traversal/filesystem security issues
        content_str = file.read().decode('utf-8', errors='ignore')
        
        logger.info(f"Parsing config for {fw_type} (length: {len(content_str)} chars)")
        
        if fw_type == 'asa':
            result = parse_asa_cli(content_str)
        elif fw_type == 'checkpoint':
            result = parse_checkpoint_csv(content_str)
        elif fw_type == 'fortigate':
            result = parse_fortigate_cli(content_str)
        elif fw_type == 'paloalto':
            result = parse_paloalto_xml(content_str)
        elif fw_type == 'ftd':
            result = parse_ftd_fmc(content_str)
        else:
            return jsonify({"error": f"Unsupported firewall type: {fw_type}"}), 400
            
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error parsing {fw_type}: {str(e)}")
        # Return a generic, safe error message to the client
        return jsonify({"error": "An error occurred while parsing the firewall configuration. Please verify the format."}), 500

if __name__ == '__main__':
    # TODO(security): Binding to 0.0.0.0 is done to allow external host access per user requirement,
    # but in production this should be restricted behind a reverse proxy or firewall/VPN.
    app.run(host='0.0.0.0', port=8001, debug=True)
