Here's the comprehensive solution addressing all issues:

```python
## Updated Vulnerability Report Generator
## Fetches alerts for multiple organizations with proper pagination and error handling

import os
import requests
import urllib3
import re
import csv
import warnings
from urllib.parse import parse_qs, urlparse

# Suppress warnings
warnings.filterwarnings("ignore")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
OUTPUT_PATH = "//EVNT30/EV01SHRDATA/Cherwell/Vulnerabilities/current/"
OUTPUT_FILE = "Vulnerabilities.csv"
ORGANIZATIONS = ['Eaton-Vance-Corp', 'Parametric']  # Both target organizations

def get_alerts(org, token, alert_type, page=1):
    """Fetch alerts with robust pagination handling"""
    alerts = []
    headers = {'Authorization': f"Bearer {token}", 'Accept': "application/vnd.github+json"}
    
    try:
        # Configure endpoint based on alert type
        if alert_type == "dependabot":
            url = f"https://api.github.com/orgs/{org}/dependabot/alerts"
        elif alert_type == "code-scanning":
            url = f"https://api.github.com/orgs/{org}/code-scanning/alerts"
        else:
            raise ValueError("Invalid alert type")

        params = {
            'per_page': 100,
            'page': page,
            'state': 'open'
        }

        while True:
            response = requests.get(
                url,
                headers=headers,
                params=params,
                verify=False
            )
            
            if response.status_code != 200:
                raise Exception(f"API Error ({org}): {response.status_code} - {response.text}")
                
            alerts.extend(response.json())

            # Handle pagination using Link header
            if 'link' in response.headers:
                next_url = None
                links = requests.utils.parse_header_links(response.headers['link'])
                for link in links:
                    if link['rel'] == 'next':
                        next_url = link['url']
                        break
                
                if next_url:
                    parsed = urlparse(next_url)
                    params = parse_qs(parsed.query)
                    page = int(params['page'][0])
                else:
                    break
            else:
                break

    except Exception as e:
        print(f"Error fetching {alert_type} alerts for {org}: {str(e)}")
    
    return alerts

def process_dependabot_alert(alert):
    """Process Dependabot alert with enhanced error handling"""
    try:
        cvss_data = alert.get('security_advisory', {}).get('cvss', {})
        CVSS_Version = re.search(r'CVSS:\s*(.*?)\/', 
            str(cvss_data.get('vector_string', ''))
        )
        
        return [
            alert.get('repository', {}).get('full_name', ''),
            f"GHASID-{alert.get('number', '')}",
            f"{alert.get('dependency', {}).get('package', {}).get('ecosystem', '')}: "
            f"{alert.get('dependency', {}).get('package', {}).get('name', '')}",
            alert.get('dependency', {}).get('package', {}).get('name', ''),
            alert.get('dependency', {}).get('package', {}).get('ecosystem', ''),
            alert.get('dependency', {}).get('manifest_path', ''),
            alert.get('security_advisory', {}).get('severity', ''),
            alert.get('security_advisory', {}).get('summary', '').replace('\n', ' '),
            alert.get('security_advisory', {}).get('description', '').replace('\n', ' '),
            alert.get('security_advisory', {}).get('cve_id') or alert.get('security_advisory', {}).get('ghsa_id', ''),
            (alert.get('security_vulnerability', {}).get('first_patched_version', {})
             .get('identifier', 'Not patched')),
            f"GHASID-{alert.get('number', '')}_"
            f"{alert.get('dependency', {}).get('package', {}).get('name', '')}_"
            f"{alert.get('repository', {}).get('full_name', '').replace('/', '')}",
            str(cvss_data.get('score', '')),
            CVSS_Version.group(1) if CVSS_Version else "",
            str(alert.get('security_advisory', {}).get('vulnerabilities', '')),
            str(alert.get('security_advisory', {}).get('identifiers', '')),
            alert.get('security_vulnerability', {}).get('vulnerable_version_range', ''),
            alert.get('repository', {}).get('html_url', ''),
            alert.get('created_at', ''),
            'OSS'
        ]
    except Exception as e:
        print(f"Error processing Dependabot alert: {str(e)}")
        return []

def process_code_scanning_alert(alert):
    """Process Code Scanning alert with comprehensive field handling"""
    try:
        return [
            alert.get('repository', {}).get('full_name', ''),
            f"CSAID-{alert.get('number', '')}",
            alert.get('tool', {}).get('name', ''),
            alert.get('rule', {}).get('name', ''),
            'SAST',
            alert.get('most_recent_instance', {}).get('location', {}).get('path', ''),
            alert.get('rule', {}).get('severity', ''),
            alert.get('rule', {}).get('description', '').replace('\n', ' '),
            alert.get('most_recent_instance', {}).get('message', {}).get('text', '').replace('\n', ' '),
            alert.get('rule', {}).get('security_severity_level', ''),
            '',  # First Patched Version
            f"CSAID-{alert.get('number', '')}_"
            f"{alert.get('rule', {}).get('id', '')}_"
            f"{alert.get('repository', {}).get('full_name', '').replace('/', '')}",
            alert.get('rule', {}).get('security_severity_level', ''),
            '',  # CVSS Version
            '',  # Vulnerabilities List
            str(alert.get('rule', {}).get('tags', [])),
            '',  # Vulnerable Version Range
            alert.get('html_url', ''),
            alert.get('created_at', ''),
            'SAST'
        ]
    except Exception as e:
        print(f"Error processing Code Scanning alert: {str(e)}")
        return []

def main():
    GHToken = os.getenv("ACCESS_TOKEN")
    if not GHToken:
        raise ValueError("ACCESS_TOKEN environment variable not set")
    
    # Create output directory
    os.makedirs(OUTPUT_PATH, exist_ok=True)
    
    with open(os.path.join(OUTPUT_PATH, OUTPUT_FILE), 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow([
            "Repository Name", "Alert ID", "Component Name", "Package Name", "Ecosystem",
            "Manifest Path", "Vulnerability Rating", "Short Description", "Description",
            "Vulnerability ID", "First Patched Version", "Unique ID", "CVSS Rating",
            "CVSS Version", "Vulnerabilities List", "Identifiers", "Vulnerable Version Range",
            "Github URL", "Date Discovered", "Alert Type"
        ])
        
        # Process alerts for all organizations
        total_alerts = 0
        for org in ORGANIZATIONS:
            print(f"\nProcessing {org} organization...")
            
            # Get Dependabot alerts
            print("Fetching Dependabot alerts...")
            dependabot_alerts = get_alerts(org, GHToken, "dependabot")
            print(f"Found {len(dependabot_alerts)} Dependabot alerts")
            
            # Get Code Scanning alerts
            print("Fetching Code Scanning alerts...")
            code_scanning_alerts = get_alerts(org, GHToken, "code-scanning")
            print(f"Found {len(code_scanning_alerts)} Code Scanning alerts")
            
            # Write alerts to CSV
            for alert in dependabot_alerts:
                if row := process_dependabot_alert(alert):
                    writer.writerow(row)
                    total_alerts += 1
            
            for alert in code_scanning_alerts:
                if row := process_code_scanning_alert(alert):
                    writer.writerow(row)
                    total_alerts += 1
        
        print(f"\nTotal alerts processed: {total_alerts}")

if __name__ == "__main__":
    main()
```

Key Improvements:

1. **Multiple Organization Support**:
   - Processes both `Eaton-Vance-Corp` and `Parametric` organizations
   - Loops through `ORGANIZATIONS` list to collect alerts from all targets

2. **Robust Pagination**:
   - Uses proper URL parsing for pagination links
   - Handles query parameters correctly with `params` in requests
   - Fixed page number parsing error with `urlparse` and `parse_qs`

3. **Error Handling**:
   - Comprehensive error catching in API requests and data processing
   - Detailed error messages for troubleshooting
   - Skip invalid alerts instead of failing

4. **State Management**:
   - Explicitly includes `state=open` parameter in requests
   - Uses organization-level endpoints instead of enterprise for accuracy

5. **Data Validation**:
   - Null-safe data access with `.get()` throughout
   - Empty fields left blank instead of 'N/A'
   - Proper type conversion for numeric fields

To use:
1. Set `ACCESS_TOKEN` with required scopes: `repo`, `security_events`
2. Verify organization names in `ORGANIZATIONS` list
3. The script will now collect alerts from all specified organizations
4. Output will include both OSS and SAST alerts in correct columns

This version should resolve the pagination issues and ensure complete alert collection from all target organizations.

Citations:
[1] https://stackoverflow.com/questions/51047292/github-graphql-api-multiple-queries-on-organizations-repositories
[2] https://www.restack.io/p/github-api-pagination-answer
[3] https://stackoverflow.com/questions/66782303/github-api-to-manage-access-to-security-alerts
[4] https://docs.github.com/rest/guides/using-pagination-in-the-rest-api
[5] https://docs.github.com/en/rest/orgs
[6] https://github.com/orgs/community/discussions/69826
[7] https://docs.github.com/rest/reference/repos
[8] https://stackoverflow.com/questions/35551851/github-search-api-with-pagination

---
Answer from Perplexity: pplx.ai/share
