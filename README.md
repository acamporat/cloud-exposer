```
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
```
                                                 
CloudExposer is a Python-based command-line interface (CLI) tool designed with an **offensive security mindset** to identify common security misconfigurations in AWS cloud environments and local Docker setups. By focusing on publicly exposed resources and overly permissive access, it helps organizations pinpoint potential **attack surface exposures** that adversaries frequently target.

This tool serves as a **lightweight, homegrown auditor** to complement larger Attack Surface Management (ASM) solutions, providing highly targeted and actionable findings.

## ✨ Features

* **AWS S3 Public Access Audit:** Scans S3 buckets for public read/write access via ACLs, bucket policies, and misconfigured Public Access Block settings.
* **AWS Security Group Open Port Audit:** Identifies Security Group ingress rules that allow traffic from `0.0.0.0/0` (the internet) to common high-risk ports (e.g., SSH, RDP, database ports).
* **Local Docker Container Audit (Optional):** Checks locally running Docker containers for privileged mode or execution as the root user, indicating potential container breakout risks.
* **Structured Output:** Provides findings in a clean, human-readable console format with colored indicators, and can output a detailed JSON file for further analysis.
* **Modular Design:** Built to be easily extensible for adding new AWS services or misconfiguration checks.

## 🚀 Getting Started

### Prerequisites

* **Python 3.6+**: Download and install from [python.org](https://www.python.org/downloads/windows/) (ensure "Add Python to PATH" is checked during installation).
* **AWS Credentials Configured**: `CloudExposer` uses your standard AWS CLI credentials. Ensure you have an AWS Access Key ID and Secret Access Key configured for the account you wish to audit (e.g., using `aws configure` or environment variables). **Always use a dedicated, non-production AWS account for testing this tool.**
* **IAM Permissions**: The AWS user/role whose credentials are used must have permissions for:
    * `s3:ListAllMyBuckets`
    * `s3:GetBucketAcl`
    * `s3:GetBucketPolicy`
    * `s3:GetBucketPublicAccessBlock`
    * `ec2:DescribeSecurityGroups`
* **Docker Desktop (Optional, for Docker checks):** If you plan to use the local Docker audit, ensure Docker Desktop is installed and running on your machine.

### Installation

1.  **Clone the repository or download the script:**
    ```bash
    git clone https://github.com/YOUR_GITHUB_USERNAME/CloudExposer.git
    cd CloudExposer
    ```
    *(If you downloaded the `.py` file directly, navigate to its directory.)*

2.  **Create and activate a Python virtual environment (recommended):**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate  # On Windows PowerShell
    # source venv/bin/activate # On Linux/macOS or Git Bash
    ```

3.  **Install required Python libraries:**
    ```bash
    pip install boto3
    pip install docker # Only if you want to enable Docker checks
    ```

## 💡 Usage

Navigate to the `CloudExposer` directory in your terminal and run the script with desired arguments.

```bash
(venv) python cloud_exposer.py [OPTIONS]

Options
--region <AWS_REGION>: Specify the AWS region to scan (e.g., us-east-1, eu-central-1). Default: us-east-1

--output <FILENAME.json>: Save findings to a JSON file (e.g., findings.json).

--no-docker: Skip the local Docker container checks.

Examples
Scan us-east-1 and print findings to console:

(venv) python cloud_exposer.py

Scan us-west-2 and save findings to scan_results.json:

(venv) python cloud_exposer.py --region us-west-2 --output scan_results.json

Scan ap-southeast-1 and skip Docker checks:

(venv) python cloud_exposer.py --region ap-southeast-1 --no-docker
```

📊 Output & Analysis
CloudExposer provides clear, colored output to your console indicating [INFO], [OK], [VULN], [ERROR], and [SKIP] messages.

When using the --output flag, findings are saved in a structured JSON format (e.g., findings.json):
```
[
    {
        "id": "S3_PUBLIC_EXPOSURE_my-vulnerable-bucket-12345",
        "type": "AWS_S3_Misconfiguration",
        "severity": "High",
        "resource_name": "my-vulnerable-bucket-12345",
        "exposure_type": "Public Access (Read/Write)",
        "details": "S3 Bucket 'my-vulnerable-bucket-12345' has potential public access. Reasons: Public READ access via ACL",
        "recommendation": "Review bucket ACLs, policies, and ensure Public Access Block is fully enabled at bucket and account levels."
    },
    {
        "id": "SG_OPEN_PORT_sg-abcdef123_80",
        "type": "AWS_SecurityGroup_Misconfiguration",
        "severity": "High",
        "resource_name": "SG: Web-App-SG (sg-abcdef123)",
        "exposure_type": "Port 80/HTTP open to 0.0.0.0/0",
        "details": "Security Group 'Web-App-SG' (sg-abcdef123) allows TCP traffic from the internet (0.0.0.0/0) to port 80 (HTTP).",
        "recommendation": "Restrict ingress to only necessary IP addresses/ranges for high-risk ports."
    }
]
```
This JSON output is invaluable for:

Data Analysis: Easily ingest into a local SQLite database or a larger data warehouse (e.g., via a Python ETL script) for powerful SQL queries, trend analysis, and correlation with other security data.

False Positive Analysis: Use structured queries to identify patterns in alerts and reduce low-fidelity findings, allowing security teams to focus on critical risks.

Reporting: Automate the generation of executive reports on attack surface exposure.

🧪 Testing Environment
CloudExposer is designed to be tested against intentionally vulnerable AWS environments. A highly recommended setup for this is AWSGoat.

AWSGoat: A deliberately vulnerable AWS infrastructure that mimics real-world misconfigurations. You can deploy it into your own dedicated AWS account for a safe testing ground.

AWSGoat GitHub Repository

Remember to always terraform destroy AWSGoat resources after testing to avoid unexpected AWS charges!

🤝 Contributing
Contributions, bug reports, and feature suggestions are welcome! Feel free to open an issue or submit a pull request.

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

📞 Contact
Author: Thomas

GitHub: acamporat
