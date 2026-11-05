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
    lab13_threat_classifier,
    lab14_resilience_planner,
    lab15_vendor_risk,
    lab16_control_classifier,
    lab17_pki_validator,
    lab18_data_protection,
    lab19_siem_alerting,
    lab20_iac_scanner,
    lab21_asset_management,
    lab22_compliance_privacy,
    lab23_audit_roe,
    lab24_awareness,
    lab25_conditional_access,
    lab26_identity_governance,
    lab27_entitlement_management,
    lab28_app_consent,
    lab29_workload_identities,
    lab30_hybrid_identity,
    lab31_identity_monitoring,
    lab32_external_identities,
    lab33_authentication_methods,
    lab34_global_secure_access,
    lab35_tenant_delegation,
    lab36_okta_groups,
    lab37_okta_admin_roles,
    lab38_okta_app_integration,
    lab39_okta_mapping_offboarding,
    lab40_okta_policy_evaluator,
    lab41_okta_password_recovery,
    lab42_okta_system_log,
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
    13: (lab13_threat_classifier, "sample_threat_scenarios.json"),
    14: (lab14_resilience_planner, "sample_resilience.json"),
    15: (lab15_vendor_risk, "sample_vendors.json"),
    16: (lab16_control_classifier, "sample_controls.json"),
    17: (lab17_pki_validator, "sample_certificates.json"),
    18: (lab18_data_protection, "sample_data_flows.json"),
    19: (lab19_siem_alerting, "sample_security_events.json"),
    20: (lab20_iac_scanner, "sample_iac.json"),
    21: (lab21_asset_management, "sample_assets.json"),
    22: (lab22_compliance_privacy, "sample_privacy_cases.json"),
    23: (lab23_audit_roe, "sample_engagement.json"),
    24: (lab24_awareness, "sample_awareness.json"),
    25: (lab25_conditional_access, "sample_signins.json"),
    26: (lab26_identity_governance, "sample_governance.json"),
    # SC-300 labs (COURSES = ("sc300",))
    27: (lab27_entitlement_management, "sample_entitlement_management.json"),
    28: (lab28_app_consent, "sample_app_consent.json"),
    29: (lab29_workload_identities, "sample_workload_identities.json"),
    30: (lab30_hybrid_identity, "sample_hybrid_identity.json"),
    31: (lab31_identity_monitoring, "sample_identity_monitoring.json"),
    32: (lab32_external_identities, "sample_external_identities.json"),
    33: (lab33_authentication_methods, "sample_authentication_methods.json"),
    34: (lab34_global_secure_access, "sample_global_secure_access.json"),
    35: (lab35_tenant_delegation, "sample_tenant_delegation.json"),
    # Okta Certified Professional labs (COURSES = ("okta",))
    36: (lab36_okta_groups, "sample_okta_groups.json"),
    37: (lab37_okta_admin_roles, "sample_okta_admin_roles.json"),
    38: (lab38_okta_app_integration, "sample_okta_app_integration.json"),
    39: (lab39_okta_mapping_offboarding, "sample_okta_mapping_offboarding.json"),
    40: (lab40_okta_policy_evaluator, "sample_okta_policy_evaluator.json"),
    41: (lab41_okta_password_recovery, "sample_okta_password_recovery.json"),
    42: (lab42_okta_system_log, "sample_okta_system_log.json"),
}


def _register_generators() -> None:
    """Labs that carry their own seeded generator (``generate_scenario(rng, policies)``) register it here."""
    from utils.scenario_generator import GENERATORS
    for n, (module, _) in LABS.items():
        if hasattr(module, "generate_scenario"):
            GENERATORS.setdefault(n, module.generate_scenario)


_register_generators()
