package attesta.policy_test

import rego.v1

import data.attesta.policy

good := {
    "secrets_scan": {"findings_count": 0},
    "vuln_scan": {"critical": 0, "high": 0},
    "branch_protection": {"protected": true},
    "coverage": {"percent": 82},
    "ml_llm_verdict": {"ml_score": 0.12, "flagged": false, "llm_verdict": null},
}

test_good_passes if {
    policy.decision == "pass" with input as good
}

test_secrets_fail_and_escalate if {
    i := object.union(good, {"secrets_scan": {"findings_count": 2}})
    policy.decision == "fail" with input as i
    policy.escalate with input as i
}

test_critical_vuln_fails if {
    i := object.union(good, {"vuln_scan": {"critical": 1, "high": 0}})
    policy.decision == "fail" with input as i
}

test_high_vuln_fails if {
    i := object.union(good, {"vuln_scan": {"critical": 0, "high": 1}})
    policy.decision == "fail" with input as i
}

test_unprotected_branch_fails if {
    i := object.union(good, {"branch_protection": {"protected": false}})
    policy.decision == "fail" with input as i
}

test_low_coverage_fails_without_escalation if {
    i := object.union(good, {"coverage": {"percent": 50}})
    policy.decision == "fail" with input as i
    not policy.escalate with input as i
}

test_malicious_verdict_fails_and_escalates if {
    i := object.union(good, {"ml_llm_verdict": {"ml_score": 0.9, "flagged": true, "llm_verdict": "malicious"}})
    policy.decision == "fail" with input as i
    policy.escalate with input as i
}

test_flagged_without_llm_verdict_fails if {
    i := object.union(good, {"ml_llm_verdict": {"ml_score": 0.6, "flagged": true, "llm_verdict": null}})
    policy.decision == "fail" with input as i
}

test_missing_input_fails_closed if {
    i := object.remove(good, ["coverage"])
    policy.decision == "fail" with input as i
}