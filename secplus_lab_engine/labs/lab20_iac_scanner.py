"""
Lab 20 — Cloud Architecture & IaC Misconfiguration Gate
=======================================================

Security+ SY0-701 objectives
----------------------------
* 3.1  Security implications of architecture models: cloud (responsibility
       matrix, hybrid, third-party vendors), infrastructure as code,
       serverless, microservices, network infrastructure (physical
       isolation/air-gapped, logical segmentation, SDN), on-premises,
       containerization, virtualization, IoT, ICS/SCADA, RTOS, embedded,
       high availability; considerations (availability, resilience, cost,
       ease of recovery, patch availability, inability to patch, ...).
* 3.3  Protecting data: data at rest / in transit (encryption).
* 4.1  Secure baselines and hardening of cloud infrastructure.
* 4.6  Identity and access management: least privilege.

How it works
------------
A pre-deployment policy-as-code gate over a simplified, Terraform-like plan
(a list of resources ``{id, type, ...properties}``). Every check in the
policy names the resource types it covers, a property, an operator and a
severity. A check passes only when the property is DECLARED and satisfies
the operator; a missing property fails (deny by default). A resource type
the policy has never reviewed is itself a finding.

    resource  = PASS (no findings) / FAIL (one or more findings, each with a fix)
    plan      = BLOCK if any critical, or more HIGH findings than allowed
                WARN  if any other finding
                PASS  otherwise

The policy also holds a shared-responsibility matrix (IaaS / PaaS / SaaS ×
layer) and a table of architecture models with their security trade-offs.

Run it
------
    python main.py lab 20
"""

from __future__ import annotations

from dataclasses import dataclass, field

TITLE = "Lab 20 — Cloud Architecture & IaC Misconfiguration Gate"
OBJECTIVES = ("SY0-701 3.1 Architecture models: cloud responsibility matrix, IaC, serverless, containers, "
              "segmentation, HA · 3.3 Data at rest/in transit · 4.1 Secure baselines · 4.6 Least privilege")
DECISIONS = ["PASS", "WARN", "BLOCK"]
SEVERITY_CHOICES = ["critical", "high", "medium", "low", "none (PASS)"]
PARTIES = {"provider": "cloud provider", "customer": "customer", "shared": "shared"}


@dataclass
class Finding:
    check: str
    title: str
    severity: str
    detail: str
    fix: str


@dataclass
class ResourceResult:
    id: str
    type: str
    status: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def worst(self) -> str:
        return self.findings[0].severity if self.findings else "none (PASS)"


@dataclass
class GateResult:
    decision: str
    reasons: list[str]
    resources: list[ResourceResult]
    counts: dict


def _admin_exposures(rules: list, cfg: dict) -> list[str]:
    hits = []
    for r in rules:
        port = str(r.get("port", ""))
        if r.get("cidr") in cfg["internet_cidrs"] and port in cfg["admin_ports"]:
            hits.append(f"{cfg['admin_ports'][port]} ({port}) from {r['cidr']}")
    return hits


def _fmt(v) -> str:
    return str(v).lower() if isinstance(v, bool) else str(v)


def evaluate_check(res: dict, check: dict, cfg: dict) -> str | None:
    """Return a failure detail, or None when the check passes."""
    prop, op = check["property"], check["op"]
    val = res.get(prop)
    if op == "has_tags":
        missing = [t for t in cfg["required_tags"] if not (val or {}).get(t)]
        return f"missing tag(s): {', '.join(missing)}" if missing else None
    if op == "multi_az_if_critical":
        tags = res.get("tags") or {}
        if tags.get(cfg["ha_tag"]["key"]) != cfg["ha_tag"]["value"]:
            return None
        zones = len(val or [])
        return (f"tagged {cfg['ha_tag']['value']} but in {zones} zone(s); needs >= {cfg['ha_min_zones']}"
                if zones < cfg["ha_min_zones"] else None)
    if val is None:
        return f"'{prop}' not declared: cannot verify (deny by default)"
    if op == "is_true":
        return None if val is True else f"{prop} = {_fmt(val)}"
    if op == "is_false":
        return None if val is False else f"{prop} = {_fmt(val)}"
    if op == "not_in":
        return f"{prop} = {val}" if val in check["value"] else None
    if op == "min":
        return f"{prop} = {val} (< {check['value']})" if not isinstance(val, (int, float)) or val < check["value"] else None
    if op == "no_open_ingress":
        hits = _admin_exposures(val, cfg)
        return "reachable from the internet: " + "; ".join(hits) if hits else None
    if op == "no_wildcard_admin":
        if not val:
            return "no statements declared: cannot verify (deny by default)"
        bad = [s for s in val if s.get("effect", "Allow") == "Allow" and s.get("action") == "*" and s.get("resource") == "*"]
        return "Allow action '*' on resource '*' (full admin)" if bad else None
    return f"unknown operator '{op}' in policy (deny by default)"


def scan_resource(res: dict, cfg: dict) -> ResourceResult:
    rid, rtype = res.get("id", "<no id>"), res.get("type")
    order = cfg["severity_order"]
    if rtype not in cfg["known_types"]:
        f = Finding("UNREVIEWED", "Unreviewed resource type", cfg["unknown_type_severity"],
                    f"type '{rtype}' has no reviewed security checks (deny by default)",
                    "Get the resource type reviewed and add checks to the policy before deploying it.")
        return ResourceResult(rid, str(rtype), "FAIL", [f])
    findings = []
    for chk in cfg["checks"]:
        if "*" in chk["types"] or rtype in chk["types"]:
            detail = evaluate_check(res, chk, cfg)
            if detail:
                findings.append(Finding(chk["id"], chk["title"], chk["severity"], detail, chk["fix"]))
    findings.sort(key=lambda f: order.index(f.severity))
    return ResourceResult(rid, rtype, "FAIL" if findings else "PASS", findings)


def gate(plan: dict, policies: dict) -> GateResult:
    cfg = policies["iac"]
    rules = cfg["decision"]
    results = [scan_resource(r, cfg) for r in plan.get("resources") or []]
    counts = {s: sum(f.severity == s for r in results for f in r.findings) for s in cfg["severity_order"]}
    if not results:
        return GateResult("BLOCK", ["plan declares no resources: nothing reviewable (deny by default)"], results, counts)
    reasons = [f"{counts[s]} {s} finding(s) (any {s} blocks)" for s in rules["block_if_any"] if counts[s]]
    if counts["high"] > rules["max_high_before_block"]:
        reasons.append(f"{counts['high']} high findings exceed the limit of {rules['max_high_before_block']}")
    if reasons:
        return GateResult("BLOCK", reasons, results, counts)
    warn = [f"{counts[s]} {s} finding(s)" for s in rules["warn_if_any"] if counts[s]]
    if warn:
        return GateResult("WARN", warn + ["deploy only with a tracked remediation"], results, counts)
    return GateResult("PASS", ["every resource passed every applicable check"], results, counts)


def responsible_party(model: str, layer: str, cfg: dict) -> str:
    return PARTIES[cfg["responsibility_matrix"].get(model, {}).get(layer, "customer")]


# --------------------------------------------------------------------------- #
# Insight
# --------------------------------------------------------------------------- #
INSIGHT = {
    "objective": "SY0-701 3.1 Security implications of architecture models: cloud, IaC, serverless, containers, segmentation, HA.",
    "concepts": [
        "Responsibility matrix: the provider always owns the physical layer; the customer always owns its data and user access.",
        "IaaS = you patch the guest OS; PaaS = you secure your code; SaaS = you configure users and data. Serverless = no OS for you to patch.",
        "Infrastructure as code makes deployments repeatable and scannable: fix the template once and every copy is fixed.",
        "Network infrastructure: air-gapped (physical isolation), logical segmentation (VLANs/subnets), SDN (central software control plane).",
        "High availability spreads critical resources across zones; considerations trade availability and resilience against cost.",
    ],
    "failure_modes": [
        "A public storage bucket or public database: the most common cloud data exposure.",
        "Security groups allowing SSH/RDP from 0.0.0.0/0 because 'it was quicker to test'.",
        "IAM policies with action '*' on resource '*' handed to CI pipelines: one leaked token = full account takeover.",
        "Privileged or root containers sharing the host kernel, and plaintext secrets in function environment variables.",
        "New resource types deployed without anyone reviewing them (unreviewed = unprotected).",
    ],
    "ai_governance": [
        "An AI agent that writes IaC must pass the same policy-as-code gate as a human: the gate, not the agent, decides.",
        "Give infrastructure agents scoped roles, never '*' on '*'; their blast radius is the permissions you grant.",
        "Deny by default: a resource or property the agent invents that the policy does not know is blocked, not trusted.",
        "Every finding carries its fix, so an agent can propose a remediation that a human reviews before re-running the gate.",
    ],
    "exam_tips": [
        "'Who patches the guest OS on IaaS?' = the customer. 'Who secures the physical data centre?' = always the provider.",
        "ICS/SCADA, IoT and embedded systems often cannot be patched: compensate with segmentation and monitoring.",
        "Air-gapped = physical isolation; VLAN/subnet = logical segmentation; SDN = control plane separated from data plane.",
        "Containers share the host kernel (lighter, less isolation); VMs have their own OS on a hypervisor (VM escape, sprawl).",
        "Microservices: smaller blast radius, larger API attack surface. RTOS: deterministic timing for real-time control.",
    ],
}


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #
def run_demo(ui, policies: dict, data: dict) -> dict:
    cfg = policies["iac"]
    plan = data["plan"]
    g = gate(plan, policies)
    ui.section(f"Step 1 — Scan the IaC plan '{plan.get('name', '?')}' ({len(g.resources)} resources)")
    ui.table("Resources", ["ID", "Type", "Status", "Worst", "Checks failed"],
             [[r.id, r.type, r.status, r.worst, ", ".join(f.check for f in r.findings) or "-"] for r in g.resources])
    ui.section("Step 2 — Findings and fixes")
    for r in g.resources:
        if not r.findings:
            continue
        ui.print(f"[bold]{r.id}[/bold] ({r.type}) → FAIL")
        for f in r.findings:
            ui.bullet(f"{f.severity.upper()} {f.check} {f.title}: {f.detail}",
                      style="red" if f.severity in ("critical", "high") else "yellow")
            ui.bullet(f"Fix: {f.fix}", style="green")
    ui.section("Step 3 — Deployment decision")
    ui.status("Gate", g.decision, "; ".join(g.reasons))
    ui.section("Step 4 — Shared-responsibility matrix (who secures what)")
    models = list(cfg["responsibility_matrix"])
    ui.table("Responsibility", ["Layer", *models],
             [[desc, *[responsible_party(m, layer, cfg) for m in models]]
              for layer, desc in cfg["responsibility_layers"].items()])
    ui.insight(INSIGHT)
    return {**{r.id: r.status for r in g.resources}, "deployment": g.decision}


# --------------------------------------------------------------------------- #
# Challenge mode
# --------------------------------------------------------------------------- #
def _props(res: dict) -> str:
    return ", ".join(f"{k}={_fmt(v)}" for k, v in res.items() if k not in ("id", "type"))


def build_challenges(policies: dict, data: dict) -> list:
    from utils.challenge import Question, choices_with

    cfg = policies["iac"]
    plan = data["plan"]
    g = gate(plan, policies)
    titles = sorted({c["title"] for c in cfg["checks"]} | {"Unreviewed resource type"})
    qs: list = []
    for res, r in zip(plan.get("resources") or [], g.resources):
        ctx = f"{r.id} ({r.type}): {_props(res)}"
        qs.append(Question(prompt=f"{r.id}: what is the highest-severity finding the gate reports?", context=ctx,
                           choices=SEVERITY_CHOICES, answer=r.worst,
                           explanation="; ".join(f"{f.severity} {f.check}: {f.detail}" for f in r.findings)
                           or "all applicable checks passed", objective="3.1"))
        if len(r.findings) == 1:
            f = r.findings[0]
            qs.append(Question(prompt=f"{r.id}: which misconfiguration did the gate flag?", context=ctx,
                               choices=choices_with(f.title, titles, key=r.id), answer=f.title,
                               explanation=f"{f.detail}. Fix: {f.fix}", objective="3.1"))
    qs.append(Question(prompt=f"What is the deployment decision for plan '{plan.get('name', '?')}'?",
                       context="Finding counts: " + ", ".join(f"{k}={v}" for k, v in g.counts.items())
                               + f"; BLOCK on any {'/'.join(cfg['decision']['block_if_any'])} or more than "
                               f"{cfg['decision']['max_high_before_block']} high",
                       choices=DECISIONS, answer=g.decision, explanation="; ".join(g.reasons), objective="3.1"))
    for model in cfg["responsibility_matrix"]:
        for layer in cfg["quiz_layers"]:
            ans = responsible_party(model, layer, cfg)
            qs.append(Question(prompt=f"In {model}, who is responsible for: {cfg['responsibility_layers'][layer].lower()}?",
                               choices=sorted(PARTIES.values()), answer=ans,
                               explanation=f"Responsibility matrix: {model} × {layer} = {ans}", objective="3.1"))
    names = sorted(cfg["architecture_models"])
    for name in names:
        trait = cfg["architecture_models"][name].split(":", 1)[0]
        qs.append(Question(prompt=f"Which architecture model is this? \"{trait}\"",
                           choices=choices_with(name, names, key=name), answer=name,
                           explanation=cfg["architecture_models"][name], objective="3.1"))
    return qs
