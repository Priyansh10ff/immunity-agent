import os
import time
import requests
import json
from datetime import datetime, timezone

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RETRIES = 5
BASE_DELAY_SECONDS = 5

KEYWORDS = [
    "LangChain",
    "LlamaIndex",
    "OpenAI",
    "Anthropic",
    "Prompt Injection",
    "CrewAI",
    "AutoGPT",
    "Vanna"
]

def map_cvss_to_severity(cvss_score):
    if not cvss_score:
        return "unknown"
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    else:
        return "low"

def map_cwe_to_type(cwes):
    """Simplified mapping of standard CWEs to Prismor AI threat types."""
    # This is a very basic mapping. In a real system, this would be much more comprehensive
    # and likely use NLP to analyze the description.
    cwe_mapping = {
        "CWE-78": "unsafe_tool_execution", # OS Command Injection
        "CWE-94": "unsafe_tool_execution", # Code Injection
        "CWE-79": "prompt_injection",      # Cross-site Scripting -> conceptually similar to prompt injection in some contexts
        "CWE-20": "prompt_injection",      # Improper Input Validation
        "CWE-200": "data_exfiltration",    # Exposure of Sensitive Information
        "CWE-400": "model_denial_of_service", # Uncontrolled Resource Consumption
        "CWE-284": "policy_bypass",        # Improper Access Control
    }
    
    for cwe in cwes:
        if cwe in cwe_mapping:
            return cwe_mapping[cwe]
    
    return "unknown"

def extract_cpe(configurations):
    """Extract affected CPE strings."""
    affected = []
    if not configurations:
        return affected
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                affected.append(match.get("criteria", "unknown-configuration"))
    return list(set(affected)) # deduplicate

def fetch_nvd_data(keyword, last_mod_start_date=None, last_mod_end_date=None):
    params = {
        "keywordSearch": keyword
    }
    # If delta dates are provided, use them. Need to ensure format is correctly ISO8601 for NVD.
    if last_mod_start_date and last_mod_end_date:
        params["lastModStartDate"] = last_mod_start_date
        params["lastModEndDate"] = last_mod_end_date

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("vulnerabilities", [])
            elif response.status_code in [403, 429]:
                 # Rate limiting
                 delay = BASE_DELAY_SECONDS * (2 ** attempt)
                 print(f"Rate limited (status {response.status_code}). Retrying in {delay} seconds...", file=sys.stderr)
                 time.sleep(delay)
            else:
                print(f"Error fetching data from NVD: {response.status_code} - {response.text}", file=sys.stderr)
                return []
        except requests.exceptions.RequestException as e:
            print(f"Network error: {e}. Retrying in {BASE_DELAY_SECONDS} seconds...", file=sys.stderr)
            time.sleep(BASE_DELAY_SECONDS)
            
    print(f"Failed to fetch data for {keyword} after {MAX_RETRIES} attempts.", file=sys.stderr)
    return []

def process_vulnerability(vuln_item):
    cve_data = vuln_item.get("cve", {})
    
    vuln_id = cve_data.get("id", "UNKNOWN-ID")
    
    descriptions = cve_data.get("descriptions", [])
    description_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available")
    
    # Extract CVSS
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
         cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
         
    severity = map_cvss_to_severity(cvss_score)
    
    # Extract CWEs
    weaknesses = cve_data.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        cwes.extend([desc.get("value") for desc in w.get("description", []) if desc.get("lang") == "en"])
    
    threat_type = map_cwe_to_type(cwes)
    
    # Extract Affected
    configurations = cve_data.get("configurations", [])
    affected = extract_cpe(configurations)
    
    # Extract References
    references = [ref.get("url") for ref in cve_data.get("references", []) if ref.get("url")]
    
    # Published date format matching
    published_nvd = cve_data.get("published", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
    
    threat_object = {
        "id": vuln_id,
        "severity": severity,
        "type": threat_type,
        "title": f"NVD Entry for {vuln_id}", # simplified title
        "description": description_text,
        "affected": affected,
        "action": "Investigate and update affected component.",
        "published": published_nvd,
        "references": references
    }
    
    return threat_object

if __name__ == "__main__":
    import sys
    
    all_threats = []
    seen_ids = set()
    
    print("Starting NVD vulnerability fetch for AI components...", file=sys.stderr)
    
    for keyword in KEYWORDS:
        print(f"Querying for keyword: {keyword}...", file=sys.stderr)
        vulns = fetch_nvd_data(keyword)
        
        for vuln in vulns:
             threat = process_vulnerability(vuln)
             vuln_id = threat["id"]
             
             if vuln_id not in seen_ids:
                 all_threats.append(threat)
                 seen_ids.add(vuln_id)
                 
        # Respect NVD API limits (even with API key, play nice)
        time.sleep(2)
        
    # Output raw JSON to stdout so it can be piped
    print(json.dumps(all_threats), file=sys.stdout)
