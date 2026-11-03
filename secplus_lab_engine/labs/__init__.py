"""
Lab registry.

Each lab module exposes:

* ``TITLE`` / ``OBJECTIVES`` – display strings
* ``INSIGHT``                – content for the Exam & Architectural Insight panel
* ``run_demo(ui, policies, data)`` – runs the example scenario, returns a summary dict
"""

from . import (
    lab1_jml_governance,
    lab2_zero_trust_evaluator,
    lab3_log_inspector,
    lab4_change_management,
    lab5_ai_agent_governor,
)

# lab number -> (module, default data file)
LABS = {
    1: (lab1_jml_governance, "sample_identities.json"),
    2: (lab2_zero_trust_evaluator, "sample_access_requests.json"),
    3: (lab3_log_inspector, "sample_logs.json"),
    4: (lab4_change_management, "sample_rfcs.json"),
    5: (lab5_ai_agent_governor, "sample_agent_actions.json"),
}
