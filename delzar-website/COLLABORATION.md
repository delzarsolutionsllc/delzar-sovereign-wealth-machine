# Delzar Solutions — Manus ↔ Claude Co-Pilot Protocol

**Project:** Delzar Solutions LLC — Cherokee Nation member-owned federal IT services company  
**Stack:** React 19 · TypeScript · Tailwind 4 · tRPC · Drizzle ORM · MySQL · Anthropic Claude API  
**Domain:** delzarsolutionsllc.com  
**Contact:** dominique@delzarsolutionsllc.com

---

## The Team

| Agent | Role | Strengths | Primary Tasks |
|---|---|---|---|
| **Manus AI** | Full-Stack Orchestrator | Code execution, file system, browser automation, API integration, deployment | Build, debug, deploy, test, database, GitHub ops |
| **Claude Anthropic** | Intelligence Engine | Deep reasoning, GovCon strategy, writing, code review, analysis | Strategy, writing, QA review, opportunity analysis, capability statements |
| **DJ (Dominique)** | Owner & Decision Maker | Domain expertise, Cherokee Nation relationships, federal contracting knowledge | Approve, direct, provide context, make final calls |

---

## Bidirectional Review Protocol

Every significant output goes through a **4-step dual-agent pipeline**:

```
Step 1: PARALLEL WORK
  Claude → works on task
  Manus  → works on task (simultaneously)

Step 2: CROSS-REVIEW
  Claude → reviews Manus output (strengths + improvements)
  Manus  → reviews Claude output (strengths + improvements)

Step 3: SYNTHESIS
  Claude → synthesizes best elements from both into final output

Step 4: IMPROVEMENT LOG
  System → identifies 3-5 improvements for next iteration
```

This eliminates blind spots, catches errors, and produces outputs that are better than either agent alone.

---

## Task Assignment Protocol

### Manus assigns to Claude: `.copilot/tasks-for-claude.json`
Use when you need:
- GovCon strategy and analysis
- Writing (capability statements, proposals, briefs)
- Code review and QA
- Complex reasoning about federal contracting
- Opportunity scoring and win probability assessment

### Claude assigns to Manus: `.copilot/tasks-for-manus.json`
Use when you need:
- Code implementation and debugging
- File system operations
- API integrations
- Database migrations
- GitHub operations
- Deployment and testing

### Task Status Flow
```
pending → in_progress → completed
```

Always update the JSON file when picking up or completing a task.

---

## Code Review Standards

When either agent reviews code, check for:

1. **Security** — No API keys in client code, all sensitive ops server-side
2. **Performance** — No N+1 queries, proper caching, optimistic updates
3. **Accessibility** — ARIA labels, keyboard navigation, color contrast
4. **TypeScript** — Strict types, no `any`, proper error handling
5. **GovCon Accuracy** — Buy Indian Act claims must be legally accurate
6. **Domain Consistency** — All references use `delzarsolutionsllc.com`

---

## Priority Hierarchy

```
CRITICAL → Act immediately (SAM.gov expiry, security issues, site down)
HIGH     → Complete within 48 hours
MEDIUM   → Complete within 1 week
LOW      → Complete when capacity allows
```

---

## Current Critical Items (as of 2026-04-12)

| Priority | Item | Owner | Deadline |
|---|---|---|---|
| 🔴 CRITICAL | SAM.gov registration renewal | DJ + Claude | April 27, 2026 |
| 🔴 CRITICAL | Buy Indian Industry Day prep | DJ + Claude | April 20, 2026 |
| 🟡 HIGH | IHS Tahlequah recompete strategy | Claude | April 19, 2026 |
| 🟡 HIGH | Contact form → real DB wiring | Manus | ASAP |
| 🟡 HIGH | Domain references update | Manus | ASAP |
| 🟢 MEDIUM | Vitest tests for co-pilot routes | Manus | April 19, 2026 |
| 🟢 MEDIUM | Opportunity analyzer UI | Manus | April 26, 2026 |

---

## Architecture Decisions

**Why Anthropic Claude as the primary LLM?**
- claude-3-5-sonnet-20241022 has superior reasoning for complex GovCon analysis
- Better at long-form professional writing (capability statements, proposals)
- More reliable structured output for opportunity scoring
- Manus built-in LLM serves as the QA/validation layer

**Why tRPC for the AI routes?**
- End-to-end type safety from server to client
- No manual REST route definitions
- Automatic error handling and loading states
- Easy to add authentication to any route

**Why server-side AI calls only?**
- API keys never exposed to client
- Rate limiting and caching can be applied server-side
- Consistent model versions across all users

---

## Improvement Loop

After each major feature, both agents run a joint retrospective:

1. **What worked well?** (keep doing)
2. **What could be better?** (improve next iteration)
3. **What should we stop doing?** (eliminate waste)
4. **What should we try next?** (experiment)

Results are logged in `.copilot/retrospectives/` and fed back into the task queue.

---

*This document is maintained by both Manus and Claude. Last updated: 2026-04-12*
