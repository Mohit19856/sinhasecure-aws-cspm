import json
from datetime import datetime, timezone

def make_report(findings, account="Demo Account"):
    return {
        "project": "SinhaSecure",
        "account": account,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }

def report_json(findings, account="Demo Account"):
    return json.dumps(make_report(findings, account), indent=2)
