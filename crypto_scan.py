#!/usr/bin/env python3
"""
CryptoMiner Scanner - Detects cryptojacking in startup scripts and containers.
Author: [Your Name]
License: MIT
Requires: pip install boto3 google-cloud-compute azure-mgmt-compute azure-identity
Setup: Configure AWS/GCP/Azure credentials via CLI/SDKs.
Run: python3 crypto_scan.py
Output: Logs to crypto_scan_*.txt
"""

import os
import platform
import re
import subprocess
import base64
from datetime import datetime
import logging

try:
    import boto3
    from google.cloud import compute_v1
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.compute import ComputeManagementClient
except ImportError:
    print("Missing cloud SDKs. Install: pip install boto3 google-cloud-compute azure-mgmt-compute azure-identity")
    exit(1)

MINER_SIGNS = [
    r"xmrig", r"stratum\+tcp://", r"minerd", r"ccminer", r"cpuminer",
    r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", r"curl\s.*\|.*bash", r"wget\s.*&&.*sh"
]

LOG_FILE = f"crypto_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s",
                    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
logger = logging.getLogger()

def check_regex(text):
    try:
        decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
        for pattern in MINER_SIGNS:
            if re.search(pattern, decoded, re.IGNORECASE) or re.search(pattern, text, re.IGNORECASE):
                return f"SUSPICIOUS: Matches {pattern}"
    except:
        pass
    for pattern in MINER_SIGNS:
        if re.search(pattern, text, re.IGNORECASE):
            return f"SUSPICIOUS: Matches {pattern}"
    return "Clean"

def run_command(cmd, shell=True):
    try:
        return subprocess.check_output(cmd, shell=shell, text=True, stderr=subprocess.DEVNULL)
    except:
        return ""

def scan_windows_startup():
    logger.info("=== Windows Startup Check ===")
    for line in run_command(r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /s').splitlines():
        if line.strip():
            logger.info(f"Registry: {line.strip()} - {check_regex(line)}")
    for line in run_command("schtasks /query /fo LIST").splitlines():
        if "TaskName" in line or "Command" in line:
            logger.info(f"Task: {line.strip()} - {check_regex(line)}")

def scan_linux_startup():
    logger.info("=== Linux Startup Check ===")
    for path in ["/etc/crontab", "/etc/cron.d/"]:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    with open(os.path.join(root, file), "r") as f:
                        for line in f:
                            logger.info(f"Cron {file}: {line.strip()} - {check_regex(line)}")
        elif os.path.isfile(path):
            with open(path, "r") as f:
                for line in f:
                    logger.info(f"Cron: {line.strip()} - {check_regex(line)}")
    for service in run_command("systemctl list-unit-files | grep .service").splitlines():
        logger.info(f"Service: {service.strip()} - {check_regex(service)}")
    if os.path.exists("/etc/rc.local"):
        with open("/etc/rc.local", "r") as f:
            for line in f:
                logger.info(f"rc.local: {line.strip()} - {check_regex(line)}")

def scan_containers():
    logger.info("=== Container Check ===")
    for cid in run_command("docker ps -q").splitlines():
        inspect = run_command(f"docker inspect {cid}")
        logger.info(f"Docker {cid} Config: {check_regex(inspect)}")
        processes = run_command(f"docker exec {cid} ps aux")
        if processes:
            logger.info(f"Docker {cid} Processes: {check_regex(processes)}")
        net = run_command(f"docker exec {cid} ss -tuln | grep -E '3333|5555|8080|14444'")
        if net:
            logger.info(f"Docker {cid} Network: {net.strip()} - SUSPICIOUS")
    for line in run_command("kubectl get pods -A -o wide").splitlines():
        if "NAME" not in line:
            pod, namespace = line.split()[:2]
            spec = run_command(f"kubectl get pod {pod} -n {namespace} -o yaml")
            logger.info(f"K8s Pod {pod} ({namespace}): {check_regex(spec)}")

def scan_aws_startup(aws_region="us-east-1"):
    logger.info("=== AWS EC2 Startup Check ===")
    try:
        ec2 = boto3.client("ec2", region_name=aws_region)
        for reservation in ec2.describe_instances()["Reservations"]:
            for instance in reservation["Instances"]:
                user_data = ec2.describe_instance_attribute(
                    InstanceId=instance["InstanceId"], Attribute="userData"
                )["UserData"].get("Value", "")
                logger.info(f"EC2 {instance['InstanceId']} UserData: {user_data[:50]}... - {check_regex(user_data)}")
    except Exception as e:
        logger.error(f"AWS Error: {e}")

def scan_gcp_startup(project_id="your-project-id", zone="us-central1-a"):
    logger.info("=== GCP Compute Engine Startup Check ===")
    try:
        client = compute_v1.InstancesClient()
        for instance in client.list(project=project_id, zone=zone):
            for item in instance.metadata.items:
                if item.key == "startup-script":
                    logger.info(f"GCE {instance.name} Startup: {item.value[:50]}... - {check_regex(item.value)}")
    except Exception as e:
        logger.error(f"GCP Error: {e}")

def scan_azure_startup(subscription_id="your-subscription-id"):
    logger.info("=== Azure VM Startup Check ===")
    try:
        credential = DefaultAzureCredential()
        client = ComputeManagementClient(credential, subscription_id)
        for vm in client.virtual_machines.list_all():
            os_profile = str(vm.os_profile or "")
            logger.info(f"Azure VM {vm.name} OS Profile: {check_regex(os_profile)}")
    except Exception as e:
        logger.error(f"Azure Error: {e}")

def main():
    logger.info(f"Scan started: {datetime.now()}")
    system = platform.system()
    if system == "Windows":
        scan_windows_startup()
    elif system == "Linux":
        scan_linux_startup()
        scan_containers()
    scan_aws_startup()
    scan_gcp_startup()
    scan_azure_startup()
    logger.info(f"Scan completed: {datetime.now()}")

if __name__ == "__main__":
    main()
