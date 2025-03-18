# CryptoMiner Scanner

A Python script to detect cryptojacking in startup scripts, containers, and cloud instances.

## Features
- Scans Windows registry and scheduled tasks.
- Checks Linux cron, systemd, and rc.local.
- Inspects Docker containers and Kubernetes pods.
- Audits AWS EC2, GCP Compute Engine, and Azure VMs.

## Requirements
- Python 3.x
- Install dependencies: `pip install boto3 google-cloud-compute azure-mgmt-compute azure-identity`
- Configure cloud credentials (AWS CLI, GCP SDK, Azure CLI).

## Usage
1. Clone the repo: `git clone https://github.com/Targetproof/crypto_scan.git`
2. Run: `python3 crypto_scan.py`
3. Check output in `crypto_scan_*.txt`.

## Notes
- Edit `aws_region`, `project_id`, `zone`, and `subscription_id` for your environment.
- False positives possible—verify suspicious hits.

## License
MIT
