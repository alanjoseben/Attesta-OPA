package attesta.policy

import rego.v1

min_coverage := 70
max_high_vulns := 0

# Fail closed: missing inputs are violations, not silent passes
required := ["secrets_scan", "vuln_scan", "branch_protection", "coverage", "ml_llm_verdict"]

violations contains v if {
    some k in required
    not input[k]
    v := {"policy": "input_present", "severity": "critical", "reason": sprintf("missing input: %s", [k])}
}

violations contains v if {
    input.secrets_scan.findings_count > 0
    v := {"policy": "no_secrets", "severity": "critical",
          "reason": sprintf("%d secret(s) found", [input.secrets_scan.findings_count])}
}

violations contains v if {
    input.vuln_scan.critical > 0
    v := {"policy": "no_critical_vulns", "severity": "high", "reason": "critical vulnerabilities present"}
}

violations contains v if {
    input.vuln_scan.high > max_high_vulns
    v := {"policy": "high_vuln_limit", "severity": "high", "reason": "high vulnerabilities exceed limit"}
}

violations contains v if {
    input.branch_protection.protected != true
    v := {"policy": "branch_protection", "severity": "high", "reason": "branch not protected / reviews missing"}
}

violations contains v if {
    input.coverage.percent < min_coverage
    v := {"policy": "min_coverage", "severity": "low",
          "reason": sprintf("coverage %v%% < %v%%", [input.coverage.percent, min_coverage])}
}

violations contains v if {
    input.ml_llm_verdict.llm_verdict == "malicious"
    v := {"policy": "malicious_code", "severity": "critical", "reason": "LLM review judged code malicious"}
}

violations contains v if {
    input.ml_llm_verdict.flagged == true
    not is_string(input.ml_llm_verdict.llm_verdict)
    v := {"policy": "malicious_code", "severity": "critical", "reason": "flagged by ML, no LLM verdict"}
}

default decision := "fail"
decision := "pass" if count(violations) == 0

escalate if {
    some v in violations
    v.severity == "critical"
}