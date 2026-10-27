# SinhaSecure – AWS Cloud Security & Compliance Auditor

SinhaSecure is a Streamlit-based Cloud Security Posture Management (CSPM) dashboard for auditing AWS environments.

## Features
- AWS account security overview
- IAM, S3, EC2 and RDS security checks
- CIS-oriented security findings
- Severity-based dashboard
- JSON report export
- Optional Prowler integration
- Demo mode for testing without AWS credentials

## Quick Start

### Windows
```powershell
cd sinhasecure-aws-cspm
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

### AWS credentials
Use the AWS CLI profile or environment variables. Do not put credentials in source code.

```powershell
aws configure
```

Then run:

```powershell
streamlit run app.py
```

### Optional Prowler
Install Prowler separately and make sure the `prowler` command is available in PATH.

```powershell
prowler aws --compliance cis_5.0_1.5.0
```

## Project Structure

```text
sinhasecure-aws-cspm/
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
├── config.py
├── auditor/
│   ├── __init__.py
│   ├── aws_auditor.py
│   ├── checks.py
│   └── prowler_runner.py
├── utils/
│   ├── __init__.py
│   ├── report.py
│   └── security.py
├── data/
│   └── demo_findings.json
└── reports/
    └── .gitkeep
```

## Security
SinhaSecure never requires AWS access keys to be written into the project. Use AWS CLI profiles, IAM roles, or environment variables.
