# MANUS ↔ CLAUDE COLLABORATION PROTOCOL
## Repo: github.com/delzarsolutionsllc/delzar-sovereign-wealth-machine

---

## RULE: Both AIs push to this repo. GitHub is the shared brain.

## FOLDER OWNERSHIP

```
delzar-sovereign-wealth-machine/
│
├── 📁 manus/                    ← MANUS WRITES HERE
│   ├── intelligence/            ← Research outputs, deep dives, sweeps
│   ├── opportunities/           ← Tribal procurement opportunities (JSON)
│   ├── competitors/             ← Competitor intelligence (JSON)
│   ├── contacts/                ← Discovered contacts (JSON)
│   ├── capability-statements/   ← Generated cap statements
│   ├── website-updates/         ← Website enhancement PRs
│   └── tasks-for-claude.json    ← Tasks Manus assigns to Claude
│
├── 📁 claude/                   ← CLAUDE WRITES HERE
│   ├── builds/                  ← Built tools, scripts, MCPs
│   ├── dashboards/              ← Dashboard updates
│   ├── automations/             ← Scheduled task configs
│   ├── deployments/             ← Deployment logs
│   └── tasks-for-manus.json     ← Tasks Claude assigns to Manus
│
├── 📁 shared/                   ← BOTH READ/WRITE
│   ├── company-data.json        ← Delzar company constants (single source of truth)
│   ├── tero-status.json         ← TERO registration tracker
│   ├── pipeline.json            ← Sales pipeline data
│   └── config.json              ← Shared configuration
│
├── index.html                   ← Public command center (Claude maintains)
├── forge.html                   ← Secret FORGE dashboard (Claude maintains)
├── delzar-website/              ← Public website (Manus enhances, Claude deploys)
├── complianceguard-mcp/         ← MCP product (Claude maintains)
└── DELZAR-INTEL/                ← Intelligence stack (both contribute)
```

## DATA FORMATS

### opportunities.json (Manus writes, Claude reads)
```json
[{
  "id": "CN-164495",
  "tribe": "Cherokee Nation",
  "title": "RFB - Transport Modular Home Sections",
  "description": "...",
  "openDate": "2026-04-10",
  "closeDate": "2026-04-20",
  "estimatedValue": "$45K",
  "naics": "484110",
  "play": "BID_DIRECT",
  "playRationale": "CDL required — DJ qualified",
  "contact": { "name": "...", "phone": "...", "email": "..." },
  "sourceUrl": "https://cherokeebids.org/...",
  "scannedAt": "2026-04-12T10:00:00Z",
  "scannedBy": "manus"
}]
```

### competitors.json (Manus writes, Claude reads)
```json
[{
  "name": "Company Name",
  "uei": "...",
  "owner": "...",
  "tribe": "...",
  "location": "...",
  "naicsCodes": ["541512", "561210"],
  "totalAwards3yr": 1500000,
  "topAgencies": ["IHS", "BIA"],
  "strengths": ["..."],
  "weaknesses": ["..."],
  "scannedAt": "...",
  "scannedBy": "manus"
}]
```

### tasks-for-claude.json (Manus writes)
```json
[{
  "id": "task-001",
  "title": "Update FORGE with 8 new Cherokee bids",
  "description": "New opportunities found in manus/opportunities/cherokee-2026-04-13.json",
  "priority": "high",
  "status": "pending",
  "createdAt": "...",
  "createdBy": "manus"
}]
```

### tasks-for-manus.json (Claude writes)
```json
[{
  "id": "task-001",
  "title": "Research IHS Oklahoma micro-purchase patterns",
  "description": "Need data on IHS Oklahoma GPC purchases under $15K for the last 2 fiscal years",
  "priority": "high",
  "status": "pending",
  "createdAt": "...",
  "createdBy": "claude"
}]
```

## COMMIT MESSAGE CONVENTIONS

- Manus commits: `[MANUS] description`
- Claude commits: `[CLAUDE] description`
- Both include: `Co-Authored-By:` header

## WORKFLOW

1. DJ tells Manus: "Scan Cherokee bids"
2. Manus scans → saves to `manus/opportunities/cherokee-2026-04-13.json` → pushes to GitHub
3. DJ tells Claude: "Check for Manus updates"
4. Claude pulls → reads `manus/opportunities/` → updates FORGE dashboard → pushes to GitHub
5. Both AIs always pull before pushing to avoid conflicts

## WHO DOES WHAT

| Task | Manus | Claude |
|------|-------|--------|
| Scan tribal procurement portals | ✅ | |
| Update FORGE dashboard with new data | | ✅ |
| Research competitors on SAM.gov | ✅ | |
| Build competitor map visualization | | ✅ |
| Generate capability statements | ✅ (research) | ✅ (FORGE tool) |
| Deploy MCP servers | | ✅ |
| Enhance public website design | ✅ | |
| Merge website updates & deploy | | ✅ |
| Run Digital Trail of Tears | ✅ | |
| Create scheduled automations | | ✅ |
| Write proposal templates | ✅ (research) | ✅ (FORGE tool) |
| Push to GitHub | ✅ | ✅ |
