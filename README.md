# AWS Internal Audit Dashboard

A Streamlit-based web application for auditing AWS accounts — covering billing, resource inventory, security posture, and cost optimization with a full-featured authentication system.

## Features Overview

### AWS Auditing
- **Multi-Account Auditing** — Add multiple AWS accounts and audit them in parallel using background jobs
- **Cost & Billing Analysis** — Monthly billing breakdown by service and region, cost forecasting, outstanding payments
- **Resource Inventory** — Scans all 27+ AWS regions for:
  - EC2 Instances, EBS Volumes, Snapshots, Elastic IPs
  - RDS Databases, Lambda Functions, ECS Clusters
  - S3 Buckets, CloudFront Distributions
  - Load Balancers (ALB/NLB/CLB) with target health
  - ElastiCache Clusters, SNS Topics, SQS Queues
  - VPCs, NAT Gateways, Route Tables
- **Service Quotas** — Monitors current usage vs. quota limits across regions
- **Organization Verification** — Checks if the account belongs to an AWS Organization

### Cost Optimization & Security
- **S3 Security Scan** — Detects publicly accessible buckets, missing encryption, and blocked public access settings
- **IAM Security Posture** — Root account MFA check, access key age analysis, console password audit, account summary
- **Idle Resource Detection** — Finds underutilized EC2 instances, unattached EBS volumes, unused Elastic IPs, idle load balancers
- **Cost Recommendations** — Actionable suggestions for cost savings with estimated monthly savings

### Reports
- **Audit Reports** — Detailed Excel reports with separate sheets for billing, resources (per region), service quotas, and organization info
- **Optimization Reports** — Excel reports covering security findings, idle resources, and cost-saving recommendations
- **Audit History** — Full history of past audits with downloadable reports

### Authentication & User Management
- **User Registration** — With email validation, password strength meter, and security question
- **Secure Login** — Bcrypt password hashing, rate limiting (5 failed attempts = 15-minute lockout)
- **Two-Factor Authentication (2FA)** — TOTP-based 2FA with QR code setup (Google Authenticator, Authy, etc.)
- **Forgot Password** — Two recovery methods:
  - Security question verification
  - Email OTP (requires SMTP configuration)
- **User Profiles** — Editable name, email, avatar color, password change, 2FA toggle

### Admin Panel
- **User Management** — View all users, enable/disable accounts, change roles, reset passwords, delete users
- **Company/Team Management** — Create companies, add/remove members, assign company roles (owner, admin, member)
- **SMTP Configuration** — Configure email server for password reset OTPs with test email functionality
- **Dashboard Stats** — Total users, active users, total audits, recent login activity

## User Roles

| Role | Description |
|------|-------------|
| **Admin** | The **first user to register** is automatically assigned the Admin role. Admins have full access to the Admin Panel — user management, company management, SMTP settings, and all audit history. |
| **User** | All subsequent registrations are assigned the User role. Users can run audits, generate reports, view their own audit history, and manage their profile. |

Admins can promote any User to Admin or demote an Admin to User from the Admin Panel.

## Prerequisites

- **Python** 3.10+
- **MySQL** 8.0+
- **AWS Credentials** — Access Key ID and Secret Access Key (provided via the UI per account)

## AWS IAM Policy

Create an IAM user with the policy provided in `AWS_User.json`. This grants **read-only** access to:

| Category | Services |
|----------|----------|
| Cost & Billing | Cost Explorer (GetCostAndUsage, GetCostForecast) |
| Compute | EC2, Lambda, ECS |
| Storage | S3 (ListBuckets, GetBucketLocation, GetPublicAccessBlock, GetEncryption) |
| Database | RDS, ElastiCache |
| Networking | ELB/ALB/NLB, CloudFront, VPC |
| Messaging | SNS, SQS |
| Identity | IAM (read-only), STS, Organizations |
| Monitoring | CloudWatch, Service Quotas |

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/aws-audit-dashboard.git
cd aws-audit-dashboard
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up MySQL database

```sql
-- Log in to MySQL
mysql -u root -p

-- Create database and user
CREATE DATABASE aws_audit CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'aws_audit'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON aws_audit.* TO 'aws_audit'@'localhost';
FLUSH PRIVILEGES;
```

The application automatically creates all required tables on first run.

### 5. Configure environment variables

```bash
export MYSQL_HOST=localhost
export MYSQL_USER=aws_audit
export MYSQL_PASSWORD=your_secure_password
export MYSQL_DATABASE=aws_audit
```

Or create a `.env` file (do not commit this):

```
MYSQL_HOST=localhost
MYSQL_USER=aws_audit
MYSQL_PASSWORD=your_secure_password
MYSQL_DATABASE=aws_audit
```

### 6. Run the application

```bash
streamlit run app.py
```

The app will be available at `http://localhost:8501`.

## First-Time Setup

1. Open the app and **register your first account** — it is automatically assigned the **Admin** role.
2. All subsequent users who register will be assigned the **User** role.
3. As Admin, go to the **Admin Panel** to:
   - Configure **SMTP settings** for email-based password resets (optional)
   - Create your **company/team** and add members
   - Manage users — promote to Admin, disable accounts, reset passwords
4. Navigate to the **Audit Dashboard**, add your AWS account credentials, select the billing month, and run your first audit.

## Project Structure

```
├── app.py                 # Main Streamlit application (UI, routing, background jobs)
├── auth.py                # Authentication backend (MySQL, bcrypt, TOTP, SMTP)
├── auditor.py             # AWS audit logic (billing, resources, quotas, organization)
├── optimizer.py           # Cost optimization & security scanning
├── report_generator.py    # Excel report generation (audit + optimization)
├── requirements.txt       # Python dependencies
├── AWS_User.json          # IAM policy for the AWS auditing user
├── .streamlit/
│   └── config.toml        # Streamlit theme configuration
└── README.md
```

## Tech Stack

- **Frontend:** Streamlit
- **Backend:** Python, Boto3 (AWS SDK)
- **Database:** MySQL 8.0
- **Authentication:** Bcrypt, PyOTP (TOTP 2FA)
- **Reports:** OpenPyXL, Pandas

## License

MIT
