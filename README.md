# Dependabot Vulnerabilities
This script reads the `critical` and `high` dependabot vulnerabilities from all repositories in the provided Github organization and prints a CSV formatted result to the console.
By default, the tool reports on vulnerabilities found in the https://github.com/harvard-lts Github org.
By passing in the `--huit` command-line argument, the tool reports on vulnerabilities found in the https://github.huit.harvard.edu/LTS enterprise Github org.

## Usage

### Setup
```bash
python3.11 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
```

### Credentials
Populate with:
- Github Token: PAT (Personal Access Token)
   - github.com, fine-grained (`Read access to Dependabot alerts, administration, and metadata`)
   - Enterprise github, classic (`repo:all, admin:read:org, admin:read:enterprise`)
- API URL for repos: provided
- API URL for dependabot alerts: provided
- API URL for repo properties: provided
```bash
cp env-example .env
vi .env
```

### Execution
```bash
source myenv/bin/activate

# harvard-lts
python dependabot_vulnerabilities.py > 2025-01-06-lts.csv

# HUIT
python dependabot_vulnerabilities.py --huit > 2025-01-06-huit.csv
```
