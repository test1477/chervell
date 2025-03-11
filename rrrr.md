Certainly! Here's the full updated script with all the changes we've discussed, including the corrected `process_code_scanning_alert` function:

```python
## Vulnerability Report Generator
## This script fetches Dependabot alerts (OSS) and Code Scanning alerts (SAST) from GitHub Enterprise and saves them to a CSV file.
## It uses the GitHub API to retrieve alerts for the entire enterprise.

import os
import json
import requests
import urllib3
import datetime
import re
import csv
import warnings

# Suppress warnings
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# File path for the CSV output
OUTPUT_PATH = "//EVNT30/EV01SHRDATA/Cherwell/Vulnerabilities/current/"
OUTPUT_FILE = "Vulnerabilities.csv"

def get_alerts(enterprise, token, alert_type, page=1):
    """Fetch alerts (Dependabot or Code Scanning) for the entire enterprise"""
    alerts = []
    headers = {'Authorization': f"Bearer {token}", 'Accept': "application/vnd.github+json"}
    
    if alert_type == "dependabot":
        url = f"https://api.github.com/enterprises/{enterprise}/dependabot/alerts"
    elif alert_type == "code-scanning":
        url = f"https://api.github.com/enterprises/{enterprise}/code-scanning/alerts"
    else:
        raise ValueError("Invalid alert type")
    
    res = requests.get(f"{url}?per_page=100&page={page}", headers=headers, verify=False)
    
    if res.status_code != 200:
        raise Exception(res)
    
    if len(res.json()) == 100:
        print(f"Page {page} being processed for {alert_type} alerts")
        alerts = res.json() + get_alerts(enterprise, token, alert_type, page+1)
    else:
        print(f"Final Page, page {page} being processed for {alert_type} alerts")
        return res.json()
    
    return alerts

def process_dependabot_alert(alert):
    """Process a Dependabot alert and return a row for CSV"""
    Vuln_ID = alert['security_advisory']['cve_id'] if alert['security_advisory']['cve_id'] else alert['security_advisory']['ghsa_id']
    CVSS_Version = re.search(r'CVSS:\s*(.*?)\/(.*)', str(alert['security_advisory']['cvss']['vector_string']))
    CVSS_Version = CVSS_Version.group(1) if CVSS_Version else ""
    
    return [
        alert['repository']['full_name'],
        f"GHASID-{alert['number']}",
        f"{alert['dependency']['package']['ecosystem']}: {alert['dependency']['package']['name']}",
        alert['dependency']['package']['name'],
        alert['dependency']['package']['ecosystem'],
        alert['dependency']['manifest_path'],
        alert['security_advisory']['severity'],
        alert['security_advisory']['summary'].replace('\n', '').replace('\r', ''),
        alert['security_advisory']['description'].replace('\n', '').replace('\r', ''),
        Vuln_ID,
        alert['security_vulnerability']['first_patched_version']['identifier'] if alert['security_vulnerability']['first_patched_version'] else "Not patched",
        f"GHASID-{alert['number']}_{alert['dependency']['package']['name']}_{alert['repository']['full_name'].replace('/', '')}",
        alert['security_advisory']['cvss'].get('score', 'N/A'),
        CVSS_Version,
        str(alert['security_advisory'].get('vulnerabilities', 'N/A')),
        str(alert['security_advisory'].get('identifiers', 'N/A')),
        alert['security_vulnerability'].get('vulnerable_version_range', 'N/A'),
        alert['repository']['html_url'],
        alert['created_at'],
        'OSS'
    ]

def process_code_scanning_alert(alert):
    """Process a Code Scanning alert and return a row for CSV"""
    return [
        alert['repository']['full_name'],
        f"CSAID-{alert.get('number', 'N/A')}",
        alert.get('tool', {}).get('name', 'N/A'),
        alert.get('rule', {}).get('name', 'N/A'),  # Package Name (using rule name)
        'SAST',  # Ecosystem (always SAST for Code Scanning)
        alert.get('most_recent_instance', {}).get('location', {}).get('path', 'N/A'),
        alert.get('rule', {}).get('severity', 'N/A'),
        alert.get('rule', {}).get('description', 'N/A').replace('\n', '').replace('\r', ''),
        alert.get('most_recent_instance', {}).get('message', {}).get('text', 'N/A').replace('\n', '').replace('\r', ''),
        alert.get('rule', {}).get('security_severity_level', 'N/A'),
        'N/A',  # First Patched Version
        f"CSAID-{alert.get('number')}_{alert.get('rule', {}).get('id')}_{alert['repository']['full_name'].replace('/', '')}",
        alert.get('rule', {}).get('security_severity_level', 'N/A'),  # CVSS Rating (using security_severity_level)
        'N/A',  # CVSS Version
        'N/A',  # Vulnerabilities List
        str(alert.get('rule', {}).get('tags', [])),  # Identifiers
        'N/A',  # Vulnerable Version Range
        alert.get('html_url', 'N/A'),
        alert.get('created_at', 'N/A'),
        'SAST'  # Alert Type
    ]

def main():
    GHToken = os.getenv("ACCESS_TOKEN")
    enterprise = 'Eaton-Vance'
    
    dependabot_alerts = get_alerts(enterprise, GHToken, "dependabot")
    code_scanning_alerts = get_alerts(enterprise, GHToken, "code-scanning")
    
    # Create the output directory if it doesn't exist
    os.makedirs(OUTPUT_PATH, exist_ok=True)
    
    # Open the CSV file for writing
    with open(os.path.join(OUTPUT_PATH, OUTPUT_FILE), 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write the header
        writer.writerow(["Repository Name", "Alert ID", "Component Name", "Package Name", "Ecosystem", "Manifest Path", 
                         "Vulnerability Rating", "Short Description", "Description", "Vulnerability ID", "First Patched Version", 
                         "Unique ID", "CVSS Rating", "CVSS Version", "Vulnerabilities List", "Identifiers", 
                         "Vulnerable Version Range", "Github URL", "Date Discovered", "Alert Type"])
        
        # Process and write Dependabot alerts (OSS)
        for alert in dependabot_alerts:
            if not alert['repository']['full_name'].startswith("Parametric/"):
                writer.writerow(process_dependabot_alert(alert))
        
        # Process and write Code Scanning alerts (SAST)
        for alert in code_scanning_alerts:
            if not alert['repository']['full_name'].startswith("Parametric/"):
                writer.writerow(process_code_scanning_alert(alert))

    print(f"Vulnerability report saved to {os.path.join(OUTPUT_PATH, OUTPUT_FILE)}")

if __name__ == "__main__":
    main()
```

This script now includes:

1. Correct handling of both Dependabot (OSS) and Code Scanning (SAST) alerts.
2. Proper alignment of SAST data with the CSV columns.
3. Safe access to dictionary keys to avoid KeyErrors.
4. Appropriate default values for fields that might not be present in all alerts.

The script will create a CSV file with both types of alerts, correctly formatted and aligned with the column headers. The SAST alerts will now have the correct information in each column, including the proper placement of the alert type at the end.

Remember to set the `ACCESS_TOKEN` environment variable with your GitHub token before running the script. Also, ensure you have the necessary permissions to access both Dependabot and Code Scanning alerts for your enterprise.

---
Answer from Perplexity: pplx.ai/share
