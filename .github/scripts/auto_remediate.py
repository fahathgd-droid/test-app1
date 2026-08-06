import os
import json
from github import Github

# --- Load environment variables safely ---
token = os.getenv("GITHUB_TOKEN")
repo_name = os.getenv("GITHUB_REPOSITORY")

if not token or not repo_name:
    print("❌ Missing GITHUB_TOKEN or GITHUB_REPOSITORY environment variable.")
    exit(1)

# --- Initialize GitHub client ---
g = Github(token)
repo = g.get_repo(repo_name)

# --- Read pip-audit results ---
vuln_file = "vulnerabilities.json"

if not os.path.exists(vuln_file):
    print(f"⚠️ No {vuln_file} file found. Skipping remediation.")
    exit(0)

with open(vuln_file, "r") as f:
    try:
        data = json.load(f)
    except json.JSONDecodeError:
        print("❌ Failed to parse vulnerabilities.json — invalid JSON format.")
        exit(1)

if not data:
    print("✅ No vulnerabilities found. Nothing to remediate.")
    exit(0)

# --- Prepare issue body ---
issue_title = "⚠️ Vulnerabilities Detected by pip-audit"
issue_body = "### The following vulnerabilities were found:\n\n"

for item in data:
    pkg = item.get("name", "Unknown")
    version = item.get("version", "Unknown")
    vuln_id = item.get("id", "N/A")
    fix_versions = ", ".join(item.get("fix_versions", [])) or "No fix available"
    issue_body += f"- **{pkg} {version}** — {vuln_id} → Fix: {fix_versions}\n"

issue_body += "\n---\n*This issue was automatically created by the security pipeline.*"

# --- Avoid duplicate issue creation ---
open_issues = repo.get_issues(state="open")
for issue in open_issues:
    if issue.title == issue_title:
        print("ℹ️ Issue already exists. Updating comment instead.")
        issue.create_comment(issue_body)
        break
else:
    repo.create_issue(title=issue_title, body=issue_body)
    print("✅ Created new vulnerability issue.")

print("🔒 Auto remediation script completed successfully.")
