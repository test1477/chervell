Here's the fully updated script addressing all the issues:

```python
## Vulnerability Report Generator
## This script fetches Dependabot alerts (OSS) and Code Scanning alerts (SAST) from GitHub Enterprise
## It uses the GitHub API to retrieve alerts and saves them to a CSV file

import os
import json
import requests
import urllib3
import re
import csv
import warnings
from datetime import datetime

# Suppress warnings
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
OUTPUT_PATH = "//EVNT30/EV01SHRDATA/Cherwell/Vulnerabilities/current/"
OUTPUT_FILE = "Vulnerabilities.csv"
ENTERPRISE = "Eaton-Vance"
EXCLUDE_PREFIX = "Parametric/"

def get_alerts(enterprise, token, alert_type):
    """Fetch alerts with proper pagination handling using Link headers"""
    alerts = []
    headers = {'Authorization': f"Bearer {token}", 'Accept': "application/vnd.github+json"}
    url = f"https://api.github.com/enterprises/{enterprise}/"
    
    if alert_type == "dependabot":
        url += "dependabot/alerts"
    elif alert_type == "code-scanning":
        url += "code-scanning/alerts"
    else:
        raise ValueError("Invalid alert type")

    page = 1
    while True:
        response = requests.get(
            f"{url}?per_page=100&page={page}&state=open",
            headers=headers,
            verify=False
        )
        
        if response.status_code != 200:
            raise Exception(f"API Error: {response.status_code} - {response.text}")
        
        alerts.extend(response.json())
        
        # Check for next page using Link header
        if "next" in response.links:
            page += 1
        else:
            break

    print(f"Fetched {len(alerts)} {alert_type} alerts")
    return alerts

def process_dependabot_alert(alert):
    """Process Dependabot alert data"""
    advisory = alert.get('security_advisory', {})
    cvss_data = advisory.get('cvss', {})
    
    # Extract CVSS version using regex
    cvss_version = ""
    if vector := cvss_data.get('vector_string'):
        match = re.search(r'CVSS:(?P\d\.\d)', vector)
        cvss_version = match.group('version') if match else ""

    return [
        alert.get('repository', {}).get('full_name', ''),
        f"GHASID-{alert.get('number', '')}",
        f"{alert.get('dependency', {}).get('package', {}).get('ecosystem', '')}: "
        f"{alert.get('dependency', {}).get('package', {}).get('name', '')}",
        alert.get('dependency', {}).get('package', {}).get('name', ''),
        alert.get('dependency', {}).get('package', {}).get('ecosystem', ''),
        alert.get('dependency', {}).get('manifest_path', ''),
        advisory.get('severity', ''),
        advisory.get('summary', '').replace('\n', ' ').replace('\r', ''),
        advisory.get('description', '').replace('\n', ' ').replace('\r', ''),
        advisory.get('cve_id') or advisory.get('ghsa_id', ''),
        alert.get('security_vulnerability', {}).get('first_patched_version', {}).get('identifier', ''),
        f"GHASID-{alert.get('number', '')}_{alert.get('dependency', {}).get('package', {}).get('name', '')}",
        cvss_data.get('score', ''),
        cvss_version,
        str(advisory.get('vulnerabilities', '')),
        str(advisory.get('identifiers', '')),
        alert.get('security_vulnerability', {}).get('vulnerable_version_range', ''),
        alert.get('repository', {}).get('html_url', ''),
        alert.get('created_at', ''),
        'OSS'
    ]

def process_code_scanning_alert(alert):
    """Process Code Scanning alert data"""
    rule = alert.get('rule', {})
    instance = alert.get('most_recent_instance', {})
    
    return [
        alert.get('repository', {}).get('full_name', ''),
        f"CSAID-{alert.get('number', '')}",
        alert.get('tool', {}).get('name', ''),
        rule.get('name', ''),
        'SAST',  # Ecosystem column
        instance.get('location', {}).get('path', ''),
        rule.get('severity', ''),
        rule.get('description', '').replace('\n', ' ').replace('\r', ''),
        instance.get('message', {}).get('text', '').replace('\n', ' ').replace('\r', ''),
        rule.get('security_severity_level', ''),
        '',  # First Patched Version (empty for SAST)
        f"CSAID-{alert.get('number', '')}_{rule.get('id', '')}",
        rule.get('security_severity_level', ''),  # CVSS Rating proxy
        '',  # CVSS Version (empty for SAST)
        '',  # Vulnerabilities List (empty)
        str(rule.get('tags', [])),
        '',  # Vulnerable Version Range (empty)
        alert.get('html_url', ''),
        alert.get('created_at', ''),
        'SAST'
    ]

def main():
    token = os.getenv("ACCESS_TOKEN")
    if not token:
        raise ValueError("GitHub token not found in environment variables")
    
    # Create output directory if needed
    os.makedirs(OUTPUT_PATH, exist_ok=True)
    
    # Get all alerts
    print("Fetching Dependabot alerts...")
    dependabot_alerts = get_alerts(ENTERPRISE, token, "dependabot")
    
    print("\nFetching Code Scanning alerts...")
    code_scanning_alerts = get_alerts(ENTERPRISE, token, "code-scanning")
    
    # Write to CSV
    output_path = os.path.join(OUTPUT_PATH, OUTPUT_FILE)
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow([
            "Repository Name", "Alert ID", "Component Name", "Package Name", "Ecosystem",
            "Manifest Path", "Vulnerability Rating", "Short Description", "Description",
            "Vulnerability ID", "First Patched Version", "Unique ID", "CVSS Rating",
            "CVSS Version", "Vulnerabilities List", "Identifiers", "Vulnerable Version Range",
            "Github URL", "Date Discovered", "Alert Type"
        ])
        
        # Process alerts
        for alert in dependabot_alerts:
            repo_name = alert.get('repository', {}).get('full_name', '')
            if not repo_name.startswith(EXCLUDE_PREFIX):
                writer.writerow(process_dependabot_alert(alert))
        
        for alert in code_scanning_alerts:
            repo_name = alert.get('repository', {}).get('full_name', '')
            if not repo_name.startswith(EXCLUDE_PREFIX):
                writer.writerow(process_code_scanning_alert(alert))

    print(f"\nSuccessfully generated report at: {output_path}")
    print(f"Total Dependabot alerts processed: {len(dependabot_alerts)}")
    print(f"Total Code Scanning alerts processed: {len(code_scanning_alerts)}")

if __name__ == "__main__":
    main()
```

Key Improvements:

1. **Pagination Fix**:
   - Now uses proper `Link` header parsing for reliable pagination
   - Handles all pages regardless of result count
   - Added state=open filter to match web UI counts

2. **Data Quality**:
   - Removed all "N/A" values (empty strings instead)
   - Added proper error handling for API calls
   - Improved null safety with nested dict.get() calls

3. **Performance**:
   - Removed recursive calls for pagination
   - Added progress reporting
   - Final count summary

4. **Code Scanning Fixes**:
   - Proper enterprise-level endpoint handling
   - Correct field mapping for SAST alerts
   - Empty values for non-applicable fields

5. **Error Handling**:
   - Added token validation
   - Better error messages for API failures
   - Safe handling of missing fields

To use this script:

1. Ensure Python 3.6+ is installed
2. Install requirements: `pip install requests`
3. Set environment variable: `export ACCESS_TOKEN=your_github_token`
4. Run script: `python vulnerability_report.py`

The script will now:
- Handle pagination properly for large result sets
- Show real-time progress of data fetching
- Provide final counts of processed alerts
- Generate cleaner output with proper empty values
- Include all open alerts from both Dependabot and Code Scanning

Let me know if you need any clarification or encounter other issues!

---
Answer from Perplexity: pplx.ai/share
