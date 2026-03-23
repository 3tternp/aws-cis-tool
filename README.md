# AWS CIS Benchmark Tool (v1.0.0)

A comprehensive, automated security compliance tool designed to audit your AWS environment against the **Center for Internet Security (CIS) AWS Foundations Benchmark v1.5**. This tool helps identify security misconfigurations in IAM, Storage (S3), Logging (CloudTrail), Monitoring (CloudWatch), and Networking (VPC/EC2).

## 🚀 Key Features

- **Dual Interface**:
  - **CLI (Command Line Interface)**: Perfect for automation pipelines and quick scans.
  - **GUI (Graphical User Interface)**: User-friendly Tkinter app for interactive use.
- **Flexible Authentication**:
  - **AWS SSO (Identity Center)**: Includes a built-in "Login via SSO" helper that handles Administrator permissions automatically.
  - **Standard Profiles**: Supports `~/.aws/credentials`.
  - **Access Keys**: Direct input of Access Key ID, Secret Key, and Session Token.
- **Advanced Reporting**:
  - **Formats**: Generates **JSON**, **HTML**, and **PDF** reports simultaneously.
  - **Evidence Collection**: Automated checks capture raw evidence (e.g., policy documents, JSON configs) embedded directly in the report for auditing.
  - **Manual Checks**: Clearly distinguishes between "Automated" checks (Pass/Fail) and "Manual" checks (requiring human review).
- **Extensible Framework**:
  - Modular Object-Oriented design allows easy addition of new CIS controls.

## 📋 Prerequisites

- Python 3.8+
- AWS CLI installed

## 🛠️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/3tternp/aws-cis-tool.git
   cd aws-cis-tool
   ```

2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

### 1. Graphical User Interface (GUI) - Recommended

Launch the interactive GUI:
```bash
python gui.py
```

**GUI Capabilities:**
- **One-Click SSO Login**: Click "Login via SSO" to open an Administrator terminal for secure authentication.
- **Live Logs**: Watch the scan progress in real-time within the app.
- **Report Selection**: Toggle JSON, HTML, or PDF outputs.
- **Profile Switching**: Easily switch between different AWS profiles or regions.
- **Changelog Viewer**: View recent changes directly in the GUI.

### 2. Command Line Interface (CLI)

Run the tool headlessly:
```bash
python main.py
```

**Options:**
- `--profile`, `-p`: AWS profile name (e.g., `my-sso-profile`).
- `--region`, `-r`: AWS region (e.g., `us-east-1`).
- `--output`, `-o`: Output format. Choices: `json`, `html`, `pdf`, `all` (default: `all`).
- `--output-dir`, `-d`: Directory to save reports (default: `reports`).
- `--changelog`: Print `CHANGELOG.md` and exit.

**Example:**
```bash
python main.py --profile production --region us-east-1 --output pdf
```

### 3. Docker

Build the image:
```bash
docker build -t aws-cis-tool .
```

Run a scan (mount your local AWS config/credentials as read-only):
```bash
docker run --rm -it \
  -v "$HOME/.aws:/home/appuser/.aws:ro" \
  -e AWS_PROFILE=default \
  aws-cis-tool -r us-east-1 -o all -d reports
```

## 🛡️ Supported CIS Benchmark Controls

The tool currently implements over **40+ checks** covering critical Level 1 & Level 2 controls:

### **1. Identity and Access Management (IAM)**
- [1.1] Root account access keys
- [1.4] Root account MFA
- [1.5] IAM User MFA (Console access)
- [1.8] Password Policy (Min length 14)
- [1.9] Password Reuse Prevention (24)
- [1.12] Unused Credentials (90 days)
- [1.13] Access Key Rotation (90 days)
- [1.16] Policy Attachment to Groups/Roles
- [1.22] No Administrative ("*:*") Policies

### **2. Storage (S3)**
- [2.1.1] S3 buckets employ encryption-at-rest
- [2.1.2] S3 Bucket Policy denies HTTP requests (SecureTransport)
- [2.1.3] MFA Delete enabled on S3 buckets
- [2.1.5] S3 Block Public Access (bucket settings)

### **3. Logging**
- [3.1] CloudTrail Enabled (Multi-region)
- [3.2] Log File Validation
- [3.3] CloudTrail S3 bucket not publicly accessible
- [3.4] CloudWatch Logs Integration
- [3.5] AWS Config Enabled
- [3.6] CloudTrail S3 bucket access logging enabled
- [3.7] CloudTrail KMS Encryption
- [3.8] KMS CMK rotation enabled
- [3.9] VPC Flow Logs Enabled

### **4. Monitoring**
- [4.1 - 4.14] **CloudWatch Log Metric Filter + Alarm suite**:
  - Unauthorized API calls, Console sign-in without MFA, Root usage.
  - IAM policy changes, CloudTrail config changes, Console failures.
  - CMK deletion, S3 policy changes, Config changes.
  - Security Group, NACL, Network Gateway, Route Table, and VPC changes.

### **5. Networking**
- [5.1] SSH (Port 22) restricted from 0.0.0.0/0
- [5.2] RDP (Port 3389) restricted from 0.0.0.0/0
- [5.3] NACLs restrict ingress to remote admin ports
- [5.4] Default Security Group restricts all traffic
- [5.5] VPC peering route tables are least access (Manual)

### **6. Security**
- [6.1] GuardDuty enabled (region)
- [6.2] Security Hub enabled (region)
- [6.3] GuardDuty enabled (all enabled regions)
- [6.4] Security Hub enabled (all enabled regions)
- [6.5] Security Hub CIS standard enabled (region)
- [6.6] EBS encryption by default enabled (region)
- [6.7] S3 account-level Block Public Access enabled
- [6.8] EC2 instances require IMDSv2
- [6.9] All EBS volumes encrypted

## 📂 Project Structure

```
aws-cis-tool/
├── aws_cis_tool/           # Core package
│   ├── checks/             # Logic for IAM, Storage, Logging, Monitoring, Networking
│   ├── auth.py             # Authentication & SSO handling
│   └── report.py           # Report generation engine (PDF/HTML/JSON)
├── reports/                # Output directory
├── CHANGELOG.md            # Change history
├── Dockerfile              # Container image definition
├── gui.py                  # Tkinter GUI entry point
├── main.py                 # CLI entry point
├── requirements.txt        # Dependencies
└── README.md               # Documentation
```

## 📝 License

This project is intended for educational and security auditing purposes. Always review findings manually before applying remediation.
