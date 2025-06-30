import boto3
import json
import argparse
import sys
from datetime import datetime
from botocore.exceptions import ClientError

# --- ANSI Color Codes ---
RESET = "\033[0m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
GRAY = "\033[90m"

# --- Utility Print Functions for Colored Output ---
def print_info(message):
    print(f"{CYAN}{BOLD}[INFO]{RESET} {message}")

def print_ok(message):
    print(f"{GREEN}[OK]{RESET} {message}")

def print_vuln(message):
    print(f"{RED}{BOLD}[VULN]{RESET} {message}")

def print_error(message):
    print(f"{RED}{BOLD}[ERROR]{RESET} {message}")

def print_skip(message):
    print(f"{YELLOW}[SKIP]{RESET} {message}")

# --- AWS S3 Public Bucket Checker ---
def check_s3_buckets(session, findings):
    """
    Checks all S3 buckets in the AWS account for public access configurations.
    Identifies buckets that are publicly readable or writable, or lack proper
    Block Public Access settings.
    """
    s3_client = session.client('s3')
    print_info("Checking S3 Buckets for public exposure...")

    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        if not buckets:
            print("       No S3 buckets found in this account.")
            return

        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False
            reasons = []

            # 1. Check Public Access Block Configuration (Account Level & Bucket Level)
            try:
                block_access_response = s3_client.get_bucket_public_access_block(Bucket=bucket_name)
                bpac = block_access_response['PublicAccessBlockConfiguration']
                
                if not bpac.get('BlockPublicAcls', True):
                    reasons.append("BlockPublicAcls is not enabled (ACLs could allow public access)")
                if not bpac.get('IgnorePublicAcls', True):
                    reasons.append("IgnorePublicAcls is not enabled (ACLs could allow public access)")
                if not bpac.get('BlockPublicPolicy', True):
                    reasons.append("BlockPublicPolicy is not enabled (Policies could allow public access)")
                if not bpac.get('RestrictPublicBuckets', True):
                    reasons.append("RestrictPublicBuckets is not enabled (Policies could allow public access)")

                if reasons: 
                    is_public = True

            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code")
                if error_code == 'NoSuchPublicAccessBlockConfiguration':
                    is_public = True
                    reasons.append("No Public Access Block configured for the bucket")
                else: 
                    reasons.append(f"AWS API Error checking Public Access Block: {error_code} - {e}")
                    is_public = True 
            except Exception as e:
                reasons.append(f"General Error checking Public Access Block: {e}")
                is_public = True

            # 2. Check Bucket ACLs (for public read/write)
            try:
                acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl_response['Grants']:
                    if 'URI' in grant['Grantee'] and 'http://acs.amazonaws.com/groups/global/AllUsers' == grant['Grantee']['URI']:
                        permission = grant['Permission']
                        if permission in ['READ', 'WRITE', 'FULL_CONTROL']:
                            reasons.append(f"Public {permission} access via ACL")
                            is_public = True
                    elif 'URI' in grant['Grantee'] and 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' == grant['Grantee']['URI']:
                        permission = grant['Permission']
                        if permission in ['READ', 'WRITE', 'FULL_CONTROL']:
                            reasons.append(f"Authenticated {permission} access via ACL (any AWS user)")
                            is_public = True

            except ClientError as e:
                reasons.append(f"AWS API Error checking Bucket ACL: {e.response.get('Error', {}).get('Code', 'Unknown')}")
                is_public = True
            except Exception as e:
                reasons.append(f"General Error checking Bucket ACL: {e}")
                is_public = True

            # 3. Check Bucket Policy (for public read/write)
            try:
                policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy = json.loads(policy_response['Policy'])

                for statement in policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        principals = statement.get('Principal')
                        if principals == '*' or (isinstance(principals, dict) and 'AWS' in principals and principals['AWS'] == '*'):
                            actions = statement.get('Action')
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            for action in actions:
                                if action.startswith('s3:Get') or action == 's3:*' or action == 's3:GetObject':
                                    reasons.append("Public READ access via Bucket Policy")
                                    is_public = True
                                elif action.startswith('s3:Put') or action == 's3:*' or action == 's3:PutObject':
                                    reasons.append("Public WRITE access via Bucket Policy")
                                    is_public = True

            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == 'NoSuchBucketPolicy':
                    pass
                else:
                    reasons.append(f"AWS API Error checking Bucket Policy: {e.response.get('Error', {}).get('Code', 'Unknown')}")
                    is_public = True
            except Exception as e:
                reasons.append(f"General Error checking Bucket Policy: {e}")
                is_public = True


            if is_public:
                findings.append({
                    "id": f"S3_PUBLIC_EXPOSURE_{bucket_name}",
                    "type": "AWS_S3_Misconfiguration",
                    "severity": "High",
                    "resource_name": bucket_name,
                    "exposure_type": "Public Access (Read/Write)",
                    "details": f"S3 Bucket '{bucket_name}' has potential public access. Reasons: {', '.join(sorted(list(set(reasons))))}",
                    "recommendation": "Review bucket ACLs, policies, and ensure Public Access Block is fully enabled at bucket and account levels."
                })
                print_vuln(f"S3 Bucket: {bucket_name} - Potential Public Access. Reasons: {', '.join(sorted(list(set(reasons))))}")
            else:
                print_ok(f"S3 Bucket: {bucket_name} - No apparent public access detected.")

    except Exception as e:
        print_error(f"Failed to list S3 buckets: {e}")

# --- AWS Security Group Open Port Checker ---
def check_security_groups(session, findings):
    """
    Checks AWS Security Groups for overly permissive ingress rules (0.0.0.0/0).
    Focuses on common high-risk ports.
    """
    ec2_client = session.client('ec2')
    print_info("Checking Security Groups for open ports to the internet...")

    high_risk_ports = {
        22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3389: "RDP",
        5900: "VNC", 21: "FTP", 20: "FTP-Data", 1433: "MSSQL", 3306: "MySQL",
        5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 9200: "Elasticsearch", 9300: "Elasticsearch (transport)",
        1521: "Oracle DB", 5000: "Common API/Web Server Port"
    }

    try:
        response = ec2_client.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])

        if not security_groups:
            print("       No Security Groups found in this region.")
            return

        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', 'N/A')

            for ip_permission in sg.get('IpPermissions', []):
                for ip_range in ip_permission.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        from_port = ip_permission.get('FromPort')
                        to_port = ip_permission.get('ToPort')
                        ip_protocol = ip_permission.get('IpProtocol')

                        if from_port is not None and to_port is not None:
                            for port in range(from_port, to_port + 1):
                                if port in high_risk_ports:
                                    findings.append({
                                        "id": f"SG_OPEN_PORT_{sg_id}_{port}",
                                        "type": "AWS_SecurityGroup_Misconfiguration",
                                        "severity": "High",
                                        "resource_name": f"SG: {sg_name} ({sg_id})",
                                        "exposure_type": f"Port {port}/{high_risk_ports[port]} open to 0.0.0.0/0",
                                        "details": f"Security Group '{sg_name}' ({sg_id}) allows {ip_protocol.upper()} traffic from the internet (0.0.0.0/0) to port {port} ({high_risk_ports[port]}).",
                                        "recommendation": "Restrict ingress to only necessary IP addresses/ranges for high-risk ports."
                                    })
                                    print_vuln(f"SG: {sg_name} ({sg_id}) - Port {port}/{high_risk_ports[port]} open to 0.0.0.0/0")
                        
                        if ip_protocol == '-1' or (from_port is None and to_port is None and ip_protocol is not None):
                            findings.append({
                                "id": f"SG_ALL_PORTS_OPEN_{sg_id}",
                                "type": "AWS_SecurityGroup_Misconfiguration",
                                "severity": "Critical",
                                "resource_name": f"SG: {sg_name} ({sg_id})",
                                "exposure_type": "All Ports/Protocols open to 0.0.0.0/0",
                                "details": f"Security Group '{sg_name}' ({sg_id}) allows ALL traffic from the internet (0.0.0.0/0).",
                                "recommendation": "Strictly limit ingress rules to only required ports and trusted IP ranges."
                            })
                            print_vuln(f"SG: {sg_name} ({sg_id}) - ALL PORTS/PROTOCOLS open to 0.0.0.0/0")

    except Exception as e:
        print_error(f"Failed to describe Security Groups: {e}")

# --- Docker Privileged/Root Container Checker (Optional) ---
def check_docker_containers(findings):
    """
    Checks locally running Docker containers for privileged mode or root user.
    Requires Docker to be installed and the Python Docker SDK.
    """
    try:
        import docker
        client = docker.from_env()
        containers = client.containers.list()
        print_info("Checking local Docker Containers for privileged/root execution...")

        if not containers:
            print("       No running Docker containers found.")
            return

        for container in containers:
            container_name = container.name
            container_id = container.id[:12] # Short ID
            attrs = container.attrs
            
            is_privileged = attrs['HostConfig']['Privileged']
            if is_privileged:
                findings.append({
                    "id": f"DOCKER_PRIVILEGED_{container_id}",
                    "type": "Docker_Misconfiguration",
                    "severity": "High",
                    "resource_name": f"Container: {container_name} ({container_id})",
                    "exposure_type": "Privileged Container",
                    "details": f"Docker container '{container_name}' is running in privileged mode. This grants it extensive host capabilities.",
                    "recommendation": "Avoid running containers in privileged mode. Restrict capabilities to only what is necessary."
                })
                print_vuln(f"Docker Container: {container_name} - Running in privileged mode.")

            container_user = attrs['Config']['User']
            if not container_user or container_user == 'root':
                findings.append({
                    "id": f"DOCKER_ROOT_USER_{container_id}",
                    "type": "Docker_Misconfiguration",
                    "severity": "Medium",
                    "resource_name": f"Container: {container_name} ({container_id})",
                    "exposure_type": "Container Running as Root",
                    "details": f"Docker container '{container_name}' is likely running as the root user. This increases the impact of a container escape.",
                    "recommendation": "Define a non-root user in your Dockerfiles (`USER nonrootuser`)."
                })
                print_vuln(f"Docker Container: {container_name} - Running as root user.")
            else:
                print_ok(f"Docker Container: {container_name} - Running as non-root user '{container_user}'.")

    except ImportError:
        print_skip("Python 'docker' SDK not found. Skipping Docker checks. Install with 'pip install docker'.")
    except Exception as e:
        print_error(f"Failed to check Docker containers: {e}")

# --- Main function ---
def main():
    parser = argparse.ArgumentParser(
        description="CloudExposer: A tool to identify common cloud (AWS) and container (Docker) security misconfigurations.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--region', type=str, default='us-east-1',
                        help="AWS region to scan (e.g., 'us-east-1', 'us-west-2').\nDefault: us-east-1")
    parser.add_argument('--output', type=str,
                        help="Optional: Output findings to a JSON file (e.g., 'findings.json').")
    parser.add_argument('--no-docker', action='store_true',
                        help="Optional: Skip Docker container checks.")

    args = parser.parse_args()

    # --- Startup Banner ---
    print(f"""{BLUE}{BOLD}
  ██████╗██╗      ██████╗ ██╗   ██╗██████╗                
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗               
██║     ██║     ██║   ██║██║   ██║██║  ██║               
██║     ██║     ██║   ██║██║   ██║██║  ██║               
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝               
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝                
                                                         
███████╗██╗  ██╗██████╗  ██████╗ ███████╗███████╗██████╗ 
██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
█████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗█████╗  ██████╔╝
██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║██╔══╝  ██╔══██╗
███████╗██╔╝ ██╗██║     ╚██████╔╝███████║███████╗██║  ██║
╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}{YELLOW}                                             Version: 1.0.0
                                             Author: Thomas
                                             Focus: Cloud & Container Security Misconfigs
{RESET}""")
    print_info(f"Starting scan for region: {args.region}")
    print("-" * 70)

    # Initialize AWS session
    try:
        session = boto3.Session(region_name=args.region)
        print_info(f"AWS session initialized for region: {args.region}")
    except Exception as e:
        print_error(f"Failed to initialize AWS session: {e}")
        print("Please ensure your AWS credentials are configured correctly (e.g., via AWS CLI or environment variables).")
        sys.exit(1)

    all_findings = []

    # Run AWS checks
    check_s3_buckets(session, all_findings)
    check_security_groups(session, all_findings)

    # Run Docker checks if not skipped
    if not args.no_docker:
        check_docker_containers(all_findings)
    else:
        print_info("Skipping Docker checks as requested.")

    # --- Summary and Output ---
    print(f"\n{BOLD}--- Scan Summary ---{RESET}")
    if all_findings:
        print_vuln(f"Total potential misconfigurations found: {len(all_findings)}")
        print("Please review the findings above and in the output file if specified.")
        
        if args.output:
            output_filename = args.output
            try:
                with open(output_filename, 'w') as f:
                    json.dump(all_findings, f, indent=4)
                print_ok(f"Findings saved to: {output_filename}")
            except Exception as e:
                print_error(f"Failed to write findings to file '{output_filename}': {e}")
    else:
        print_ok("No significant misconfigurations detected during this scan. Great job!")

    print(f"\n{BOLD}--- Next Steps for Analysis (Interview Prep Insight) ---{RESET}")
    print("This structured output (especially if saved to JSON) can be easily ingested into:")
    print("1. A local SQLite database for quick SQL queries (e.g., 'SELECT * FROM findings WHERE severity = \"High\";').")
    print("2. A larger data warehouse (e.g., via a Python ETL script) for trend analysis, correlation with other security data, and executive reporting.")
    print("This allows for efficient false positive analysis and helps focus remediation efforts on the most critical risks, demonstrating the 'data analysis' and 'automation' skills.")
    print("-" * 70)


if __name__ == "__main__":
    main()
