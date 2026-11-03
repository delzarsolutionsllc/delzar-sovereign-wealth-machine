"""
Lab registry.

Each lab module exposes:

* ``TITLE`` / ``OBJECTIVES`` – display strings
* ``INSIGHT``                – content for the Exam & Architectural Insight panel
* ``run_demo(ui, policies, data)`` – runs the example scenario, returns a summary dict
* ``build_challenges(policies, data)`` – predict-the-outcome questions for challenge mode
"""

from . import (
    lab1_jml_governance,
    lab2_zero_trust_evaluator,
    lab3_log_inspector,
    lab4_change_management,
    lab5_ai_agent_governor,
    lab6_risk_management,
    lab7_incident_response,
    lab8_soc_pipeline,
    lab9_vulnerability_triage,
    lab10_email_security,
    lab11_firewall_auditor,
    lab12_baseline_checker,
)

# lab number -> (module, default data file)
LABS = {
    1: (lab1_jml_governance, "sample_identities.json"),
    2: (lab2_zero_trust_evaluator, "sample_access_requests.json"),
    3: (lab3_log_inspector, "sample_logs.json"),
    4: (lab4_change_management, "sample_rfcs.json"),
    5: (lab5_ai_agent_governor, "sample_agent_actions.json"),
    6: (lab6_risk_management, "sample_risks.json"),
    7: (lab7_incident_response, "sample_incident.json"),
    8: (lab8_soc_pipeline, "sample_pipeline.json"),
    9: (lab9_vulnerability_triage, "sample_vulns.json"),
    10: (lab10_email_security, "sample_emails.json"),
    11: (lab11_firewall_auditor, "sample_firewall.json"),
    12: (lab12_baseline_checker, "sample_hosts.json"),
}
