# AWS Internal Audit Dashboard

A Streamlit-based web application for auditing AWS accounts — covering billing, resource inventory, security posture, and cost optimization.

## Features

- **Multi-Account AWS Auditing** — Audit multiple AWS accounts in parallel with background job processing
- **Cost Analysis** — Billing breakdown by service and region, cost forecasting
- **Resource Inventory** — Scans all AWS regions for EC2, RDS, Lambda, ECS, S3, ELB, ElastiCache, SNS, SQS, CloudFront, VPCs, NAT Gateways, EIPs, and more
- **Security & Optimization** — S3 bucket security checks, IAM security posture, idle resource detection, cost-saving recommendations
- **Service Quotas** — Monitors usage against service quota limits
- **Organization Verification** — Checks AWS Organizations membership
- **Excel Reports** — Auto-generated audit and optimization reports (.xlsx)
- **User Authentication** — Registration, login with rate limiting, forgot password (security question + email OTP), two-factor authentication (TOTP)
- **Admin Panel** — User management, company/team management, SMTP configuration, audit history
- **User Profiles** — Avatar, password change, 2FA setup

## Prerequisites

- **Python** 3.10+
- **MySQL** 8.0+
- **AWS CLI** configured with credentials (or provide Access Key / Secret Key in the UI)

## AWS IAM Policy

Create an IAM user with the policy in `AWS_User.json`. This grants read-only access to:
- Cost Explorer, EC2, RDS, Lambda, ECS, S3, ELB, ElastiCache, SNS, SQS, CloudFront
- IAM, Organizations, Service Quotas, CloudWatch

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

```bash
# Log in to MySQL
mysql -u root -p

# Create database and user
CREATE DATABASE aws_audit CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'aws_audit'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON aws_audit.* TO 'aws_audit'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

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

1. Open the app and register your first account — it will automatically be assigned the **Admin** role.
2. (Optional) Go to **Admin Panel > SMTP Settings** to configure email-based password resets.
3. Create your company/team in the Admin Panel.
4. Add AWS account credentials in the audit dashboard to start auditing.

## Project Structure

```
├── app.py                 # Main Streamlit application
├── auth.py                # Authentication backend (MySQL)
├── auditor.py             # AWS audit logic (billing, resources, quotas)
├── optimizer.py           # Cost optimization & security scanning
├── report_generator.py    # Excel report generation
├── requirements.txt       # Python dependencies
├── AWS_User.json          # IAM policy for the auditing user
├── .streamlit/
│   └── config.toml        # Streamlit theme configuration
└── README.md
```

## License

MIT
