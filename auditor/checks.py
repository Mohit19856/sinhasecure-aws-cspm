from datetime import datetime, timezone

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

def finding(check_id, title, service, severity, status, description, recommendation, resource="Account"):
    return {
        "check_id": check_id,
        "title": title,
        "service": service,
        "severity": severity,
        "status": status,
        "description": description,
        "recommendation": recommendation,
        "resource": resource,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

def demo_findings():
    return [
        finding("IAM-001", "Root account MFA is enabled", "IAM", "Critical", "PASS",
                "MFA protection is configured for the root account.",
                "Keep MFA enabled and use hardware MFA where appropriate."),
        finding("IAM-002", "IAM users have console passwords", "IAM", "Medium", "FAIL",
                "One or more IAM users can authenticate with console passwords.",
                "Prefer federation/Identity Center and remove unnecessary IAM user passwords."),
        finding("S3-001", "S3 buckets are not publicly accessible", "S3", "Critical", "PASS",
                "Public access blocking is enabled for audited buckets.",
                "Keep S3 Block Public Access enabled unless a documented exception exists."),
        finding("S3-002", "S3 bucket encryption", "S3", "High", "FAIL",
                "At least one bucket does not have default server-side encryption.",
                "Enable SSE-S3 or SSE-KMS as appropriate."),
        finding("EC2-001", "Security groups restrict SSH access", "EC2", "High", "FAIL",
                "A security group allows SSH from a broad internet range.",
                "Restrict SSH to trusted networks or use Systems Manager Session Manager."),
        finding("EC2-002", "Security groups restrict RDP access", "EC2", "High", "PASS",
                "No unrestricted RDP ingress was detected.",
                "Keep RDP restricted and prefer Systems Manager."),
        finding("RDS-001", "RDS instances are not publicly accessible", "RDS", "Critical", "PASS",
                "Audited RDS instances are configured as not publicly accessible.",
                "Keep databases private and reachable only from required application networks."),
        finding("RDS-002", "RDS storage encryption", "RDS", "High", "FAIL",
                "An RDS instance may not have storage encryption enabled.",
                "Enable encryption using an approved KMS key."),
    ]
