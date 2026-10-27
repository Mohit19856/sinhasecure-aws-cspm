def severity_counts(findings):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in findings:
        severity = item.get("severity", "Info")
        counts[severity] = counts.get(severity, 0) + 1
    return counts

def failed_findings(findings):
    return [f for f in findings if f.get("status") == "FAIL"]

def compliance_score(findings):
    if not findings:
        return 100.0
    applicable = [f for f in findings if f.get("status") in {"PASS", "FAIL"}]
    if not applicable:
        return 0.0
    passed = sum(f["status"] == "PASS" for f in applicable)
    return round((passed / len(applicable)) * 100, 1)
