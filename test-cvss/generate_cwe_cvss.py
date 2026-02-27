import requests
import time
from collections import defaultdict
from tqdm import tqdm
import json

API_KEY = ""  # Optional: put NVD API key here
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

headers = {}
if API_KEY:
    headers["apiKey"] = API_KEY

start_index = 0
results_per_page = 2000  # max allowed
total_results = 1

cwe_scores = defaultdict(list)

print("Fetching CVEs from NVD...")

while start_index < total_results:
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }

    response = requests.get(BASE_URL, params=params, headers=headers)
    data = response.json()

    total_results = data.get("totalResults", 0)

    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})

        # Extract CVSS v3.1
        metrics = cve.get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31", [])

        if not cvss_list:
            continue

        base_score = cvss_list[0]["cvssData"]["baseScore"]

        # Extract CWE
        weaknesses = cve.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                cwe_id = desc.get("value")
                if cwe_id and cwe_id.startswith("CWE-"):
                    cwe_scores[cwe_id].append(base_score)

    print(f"Processed {start_index + results_per_page} / {total_results}")
    start_index += results_per_page
    time.sleep(1)  # avoid rate limiting

# Compute mean CVSS per CWE
cwe_mean = {}

for cwe, scores in cwe_scores.items():
    if scores:
        mean_score = sum(scores) / len(scores)
        cwe_mean[cwe] = round(mean_score, 2)

# Save to JSON
with open("cwe_base_impact.json", "w") as f:
    json.dump(cwe_mean, f, indent=2)

print("Generated cwe_base_impact.json successfully.")