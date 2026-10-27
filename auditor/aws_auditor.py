import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from .checks import finding

class AWSAuditor:
    def __init__(self, profile=None, region="ap-south-1"):
        session_kwargs = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        self.session = boto3.Session(**session_kwargs)
        self.region = self.session.region_name or region

    def account_id(self):
        sts = self.session.client("sts")
        return sts.get_caller_identity()["Account"]

    def run(self):
        findings = []
        try:
            findings.extend(self.check_s3())
            findings.extend(self.check_ec2())
            findings.extend(self.check_rds())
            findings.extend(self.check_iam())
        except (BotoCoreError, ClientError, NoCredentialsError) as exc:
            raise RuntimeError(f"AWS audit could not be completed: {exc}") from exc
        return findings

    def check_s3(self):
        out = []
        s3 = self.session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        if not buckets:
            return [finding("S3-000", "No S3 buckets found", "S3", "Info", "PASS",
                             "No S3 buckets were returned for this account.",
                             "Create buckets only when required.")]

        for b in buckets:
            name = b["Name"]
            try:
                public = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                blocked = all(public.get(k, False) for k in (
                    "BlockPublicAcls", "IgnorePublicAcls",
                    "BlockPublicPolicy", "RestrictPublicBuckets"
                ))
            except ClientError:
                blocked = False

            out.append(finding(
                "S3-001", "S3 Block Public Access", "S3", "Critical",
                "PASS" if blocked else "FAIL",
                f"Bucket {name} public-access blocking configuration was evaluated.",
                "Enable all S3 Block Public Access settings.",
                name
            ))
        return out

    def check_ec2(self):
        out = []
        ec2 = self.session.client("ec2")
        groups = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in groups:
            for permission in sg.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                protocol = permission.get("IpProtocol")
                if protocol == "-1" or from_port in (22, 3389):
                    unrestricted = any(
                        r.get("CidrIp") == "0.0.0.0/0"
                        for r in permission.get("IpRanges", [])
                    )
                    if unrestricted:
                        port_name = "SSH" if from_port == 22 else "RDP" if from_port == 3389 else "all traffic"
                        out.append(finding(
                            "EC2-001" if from_port == 22 else "EC2-002",
                            f"Unrestricted {port_name} ingress",
                            "EC2", "High", "FAIL",
                            f"Security group {sg.get('GroupId')} permits {port_name} from 0.0.0.0/0.",
                            "Restrict ingress to trusted CIDRs or use AWS Systems Manager.",
                            sg.get("GroupId", "unknown")
                        ))
        if not out:
            out.append(finding("EC2-003", "No unrestricted SSH/RDP detected", "EC2", "High", "PASS",
                               "No unrestricted SSH or RDP ingress was found in the scanned security groups.",
                               "Continue reviewing security groups regularly."))
        return out

    def check_rds(self):
        out = []
        rds = self.session.client("rds")
        dbs = rds.describe_db_instances().get("DBInstances", [])
        for db in dbs:
            identifier = db["DBInstanceIdentifier"]
            public = db.get("PubliclyAccessible", False)
            encrypted = db.get("StorageEncrypted", False)
            out.append(finding("RDS-001", "RDS public accessibility", "RDS", "Critical",
                               "FAIL" if public else "PASS",
                               f"RDS instance {identifier} public accessibility was evaluated.",
                               "Set PubliclyAccessible to false unless there is a documented exception.",
                               identifier))
            out.append(finding("RDS-002", "RDS storage encryption", "RDS", "High",
                               "PASS" if encrypted else "FAIL",
                               f"RDS instance {identifier} storage encryption was evaluated.",
                               "Enable RDS storage encryption.",
                               identifier))
        return out

    def check_iam(self):
        out = []
        iam = self.session.client("iam")
        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            root_mfa = summary.get("AccountMFAEnabled", 0) == 1
            out.append(finding("IAM-001", "Root account MFA", "IAM", "Critical",
                               "PASS" if root_mfa else "FAIL",
                               "AWS account-level MFA status was evaluated.",
                               "Enable MFA on the AWS root account."))
        except ClientError:
            out.append(finding("IAM-001", "Root account MFA", "IAM", "Critical", "UNKNOWN",
                               "The root MFA status could not be evaluated with the current permissions.",
                               "Grant the required read permissions and re-run the audit."))
        return out
