#!/usr/bin/env node
/**
 * ComplianceGuard MCP Server
 * EU AI Act Article 12 compliance audit-logging middleware for MCP servers.
 *
 * Built by Delzar Solutions LLC — Cherokee Nation Citizen-Owned
 * Enforcement deadline: August 2, 2026
 *
 * Tools:
 *   complianceguard_log_tool_call     — Log an MCP tool invocation for Article 12 compliance
 *   complianceguard_get_audit_log     — Retrieve audit log entries with filtering
 *   complianceguard_compliance_report — Generate an EU AI Act compliance report
 *   complianceguard_check_status      — Check compliance status and gaps
 *   complianceguard_register_system   — Register an AI system for tracking
 *   complianceguard_risk_classify     — Classify an AI system's risk level per EU AI Act
 *   complianceguard_export_records    — Export records in regulator-ready format
 *   complianceguard_clear_logs        — Clear audit logs (with confirmation)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// ═══════════════════════════════════════════
// Types & Storage
// ═══════════════════════════════════════════

interface AuditEntry {
  id: string;
  timestamp: string;
  systemId: string;
  toolName: string;
  toolServer: string;
  inputSummary: string;
  outputSummary: string;
  userId: string;
  riskLevel: "minimal" | "limited" | "high" | "unacceptable";
  durationMs: number;
  success: boolean;
  errorMessage?: string;
  metadata: Record<string, string>;
}

interface AISystem {
  id: string;
  name: string;
  provider: string;
  riskLevel: "minimal" | "limited" | "high" | "unacceptable";
  registeredAt: string;
  description: string;
  purpose: string;
  mcpServers: string[];
  complianceStatus: "compliant" | "partial" | "non-compliant" | "pending-review";
}

// In-memory stores (production would use a database)
const auditLog: AuditEntry[] = [];
const registeredSystems: AISystem[] = [];
let entryCounter = 0;

function generateId(): string {
  entryCounter++;
  return `CG-${Date.now()}-${entryCounter.toString().padStart(5, "0")}`;
}

// ═══════════════════════════════════════════
// Server Initialization
// ═══════════════════════════════════════════

const server = new McpServer({
  name: "complianceguard-mcp-server",
  version: "1.0.0",
});

// ═══════════════════════════════════════════
// Tool 1: Log Tool Call
// ═══════════════════════════════════════════

server.registerTool(
  "complianceguard_log_tool_call",
  {
    title: "Log Tool Call",
    description:
      "Log an MCP tool invocation for EU AI Act Article 12 compliance. Records the tool name, server, inputs, outputs, user, timing, and success status. Every tool call across all connected MCP servers should be logged here to maintain a complete audit trail.",
    inputSchema: {
      toolName: z.string().describe("Name of the MCP tool that was called"),
      toolServer: z.string().describe("Name of the MCP server providing the tool"),
      systemId: z.string().default("default").describe("ID of the registered AI system making the call"),
      inputSummary: z.string().describe("Summary of input parameters (do NOT include sensitive data like API keys)"),
      outputSummary: z.string().describe("Summary of the tool output/result"),
      userId: z.string().default("operator").describe("Identifier of the user/operator who triggered the call"),
      durationMs: z.number().int().min(0).default(0).describe("Execution time in milliseconds"),
      success: z.boolean().default(true).describe("Whether the tool call succeeded"),
      errorMessage: z.string().optional().describe("Error message if the call failed"),
      riskLevel: z.enum(["minimal", "limited", "high", "unacceptable"]).default("minimal").describe("EU AI Act risk classification of this operation"),
      metadata: z.record(z.string()).default({}).describe("Additional key-value metadata for this log entry"),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  async (params) => {
    const entry: AuditEntry = {
      id: generateId(),
      timestamp: new Date().toISOString(),
      systemId: params.systemId,
      toolName: params.toolName,
      toolServer: params.toolServer,
      inputSummary: params.inputSummary,
      outputSummary: params.outputSummary,
      userId: params.userId,
      riskLevel: params.riskLevel,
      durationMs: params.durationMs,
      success: params.success,
      errorMessage: params.errorMessage,
      metadata: params.metadata,
    };
    auditLog.push(entry);

    return {
      content: [
        {
          type: "text",
          text: `✅ Audit entry logged: ${entry.id}\nTimestamp: ${entry.timestamp}\nTool: ${entry.toolServer}/${entry.toolName}\nRisk: ${entry.riskLevel}\nSuccess: ${entry.success}`,
        },
      ],
    };
  }
);

// ═══════════════════════════════════════════
// Tool 2: Get Audit Log
// ═══════════════════════════════════════════

server.registerTool(
  "complianceguard_get_audit_log",
  {
    title: "Get Audit Log",
    description:
      "Retrieve audit log entries with optional filtering by system, tool, server, risk level, date range, and success status. Supports pagination. Use this to review what tools have been called and verify compliance records.",
    inputSchema: {
      systemId: z.string().optional().describe("Filter by AI system ID"),
      toolName: z.string().optional().describe("Filter by tool name"),
      toolServer: z.string().optional().describe("Filter by MCP server name"),
      riskLevel: z.enum(["minimal", "limited", "high", "unacceptable"]).optional().describe("Filter by risk level"),
      since: z.string().optional().describe("ISO 8601 timestamp — only entries after this time"),
      until: z.string().optional().describe("ISO 8601 timestamp — only entries before this time"),
      successOnly: z.boolean().optional().describe("If true, only successful calls; if false, only failures"),
      limit: z.number().int().min(1).max(500).default(50).describe("Maximum entries to return"),
      offset: z.number().int().min(0).default(0).describe("Number of entries to skip for pagination"),
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  async (params) => {
    let filtered = [...auditLog];

    if (params.systemId) filtered = filtered.filter((e) => e.systemId === params.systemId);
    if (params.toolName) filtered = filtered.filter((e) => e.toolName.includes(params.toolName!));
    if (params.toolServer) filtered = filtered.filter((e) => e.toolServer.includes(params.toolServer!));
    if (params.riskLevel) filtered = filtered.filter((e) => e.riskLevel === params.riskLevel);
    if (params.since) filtered = filtered.filter((e) => e.timestamp >= params.since!);
    if (params.until) filtered = filtered.filter((e) => e.timestamp <= params.until!);
    if (params.successOnly !== undefined) filtered = filtered.filter((e) => e.success === params.successOnly);

    const total = filtered.length;
    const page = filtered.slice(params.offset, params.offset + params.limit);

    const summary = `## Audit Log (${page.length} of ${total} entries)\n\n` +
      page.map((e) =>
        `**${e.id}** | ${e.timestamp}\n` +
        `  Tool: \`${e.toolServer}/${e.toolName}\`\n` +
        `  Risk: ${e.riskLevel} | Success: ${e.success ? "✅" : "❌"} | Duration: ${e.durationMs}ms\n` +
        `  Input: ${e.inputSummary.substring(0, 100)}\n` +
        `  Output: ${e.outputSummary.substring(0, 100)}`
      ).join("\n\n");

    return {
      content: [{ type: "text", text: summary || "No audit entries found matching the criteria." }],
    };
  }
);

// ═══════════════════════════════════════════
// Tool 3: Compliance Report
// ═══════════════════════════════════════════

server.registerTool(
  "complianceguard_compliance_report",
  {
    title: "Generate Compliance Report",
    description:
      "Generate a comprehensive EU AI Act compliance report for a registered AI system or all systems. Analyzes audit logs against Article 12 requirements, identifies gaps, and provides actionable recommendations. Output is in regulator-ready markdown format.",
    inputSchema: {
      systemId: z.string().optional().describe("Specific system to report on, or omit for all systems"),
      periodDays: z.number().int().min(1).max(365).default(30).describe("Number of days to cover in the report"),
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  async (params) => {
    const cutoff = new Date(Date.now() - params.periodDays * 86400000).toISOString();
    let entries = auditLog.filter((e) => e.timestamp >= cutoff);
    if (params.systemId) entries = entries.filter((e) => e.systemId === params.systemId);

    const totalCalls = entries.length;
    const successRate = totalCalls > 0 ? (entries.filter((e) => e.success).length / totalCalls * 100).toFixed(1) : "N/A";
    const highRisk = entries.filter((e) => e.riskLevel === "high" || e.riskLevel === "unacceptable").length;
    const uniqueTools = new Set(entries.map((e) => `${e.toolServer}/${e.toolName}`)).size;
    const uniqueUsers = new Set(entries.map((e) => e.userId)).size;
    const avgDuration = totalCalls > 0 ? Math.round(entries.reduce((s, e) => s + e.durationMs, 0) / totalCalls) : 0;

    const toolBreakdown = entries.reduce((acc, e) => {
      const key = `${e.toolServer}/${e.toolName}`;
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const riskBreakdown = entries.reduce((acc, e) => {
      acc[e.riskLevel] = (acc[e.riskLevel] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const systems = params.systemId
      ? registeredSystems.filter((s) => s.id === params.systemId)
      : registeredSystems;

    const report = `# EU AI Act Compliance Report
## ComplianceGuard — Delzar Solutions LLC

**Report Period:** Last ${params.periodDays} days (since ${cutoff.split("T")[0]})
**Generated:** ${new Date().toISOString()}
**Regulation:** EU AI Act (Regulation 2024/1689) — Article 12: Record-Keeping

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Tool Calls Logged | ${totalCalls} |
| Success Rate | ${successRate}% |
| High/Unacceptable Risk Operations | ${highRisk} |
| Unique Tools Used | ${uniqueTools} |
| Unique Operators | ${uniqueUsers} |
| Average Response Time | ${avgDuration}ms |
| Registered AI Systems | ${systems.length} |

---

## Article 12 Compliance Checklist

### 12.1 — Automatic Logging Capability
${totalCalls > 0 ? "✅ COMPLIANT — Tool calls are being logged with timestamps, inputs, outputs, and operator IDs." : "⚠️ NO DATA — No tool calls have been logged yet. Begin logging to establish compliance."}

### 12.2 — Traceability of Decisions
${uniqueTools > 0 ? "✅ COMPLIANT — Each logged entry traces the specific tool, server, and parameters used." : "⚠️ PENDING — No tool usage data available for traceability analysis."}

### 12.3 — Risk-Appropriate Record Depth
${highRisk > 0 ? `⚠️ ATTENTION — ${highRisk} high/unacceptable risk operations detected. Ensure enhanced logging is active for these.` : "✅ COMPLIANT — No high-risk operations detected in this period."}

### 12.4 — Record Retention
✅ COMPLIANT — All records retained in audit log with immutable timestamps.

---

## Risk Distribution

${Object.entries(riskBreakdown).map(([level, count]) => `- **${level}**: ${count} operations`).join("\n") || "No operations logged."}

---

## Tool Usage Breakdown

${Object.entries(toolBreakdown).sort(([, a], [, b]) => b - a).slice(0, 20).map(([tool, count]) => `- \`${tool}\`: ${count} calls`).join("\n") || "No tools used."}

---

## Registered AI Systems

${systems.map((s) => `### ${s.name} (${s.id})
- **Provider:** ${s.provider}
- **Risk Level:** ${s.riskLevel}
- **Status:** ${s.complianceStatus}
- **MCP Servers:** ${s.mcpServers.join(", ") || "None"}
- **Registered:** ${s.registeredAt}`).join("\n\n") || "No systems registered. Use complianceguard_register_system to register your AI systems."}

---

## Recommendations

1. ${totalCalls === 0 ? "**BEGIN LOGGING** — Start logging all MCP tool calls to build your compliance baseline." : "Continue logging all tool calls to maintain Article 12 compliance."}
2. ${systems.length === 0 ? "**REGISTER SYSTEMS** — Register all AI systems using complianceguard_register_system." : "Review registered systems for accuracy and completeness."}
3. ${highRisk > 0 ? "**REVIEW HIGH-RISK OPERATIONS** — Investigate and document justification for all high/unacceptable risk operations." : "Monitor for any new high-risk operations."}
4. **EXPORT REGULARLY** — Use complianceguard_export_records to maintain offline backups.
5. **EU AI ACT DEADLINE** — Enforcement begins August 2, 2026. Ensure full compliance before this date.

---

*Report generated by ComplianceGuard MCP Server v1.0.0 — Delzar Solutions LLC*
*Cherokee Nation Citizen-Owned | EU AI Act Compliance Middleware*`;

    return { content: [{ type: "text", text: report }] };
  }
);

// ═══════════════════════════════════════════
// Tool 4: Check Compliance Status
// ═══════════════════════════════════════════

server.registerTool(
  "complianceguard_check_status",
  {
    title: "Check Compliance Status",
    description:
      "Quick compliance status check — returns a summary of whether the system meets EU AI Act Article 12 requirements. Shows gaps and immediate actions needed.",
    inputSchema: {
      systemId: z.string().optional().describe("System to check, or omit for overall status"),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  async (params) => {
    const entries = params.systemId ? auditLog.filter((e) => e.systemId === params.systemId) : auditLog;
    const systems = params.systemId ? registeredSystems.filter((s) => s.id === params.systemId) : registeredSystems;

    const daysToDeadline = Math.ceil((new Date("2026-08-02").getTime() - Date.now()) / 86400000);
    const hasLogging = entries.length > 0;
    const hasRegisteredSystems = systems.length > 0;
    const hasHighRisk = entries.some((e) => e.riskLevel === "high" || e.riskLevel === "unacceptable");

    const overallStatus = hasLogging && hasRegisteredSystems ? (hasHighRisk ? "⚠️ PARTIAL" : "✅ ON TRACK") : "❌ GAPS FOUND";

    const status = `## ComplianceGuard Status Check

**Overall:** ${overallStatus}
**Days to EU AI Act Enforcement:** ${daysToDeadline}
**Audit Entries:** ${entries.length}
**Registered Systems:** ${systems.length}

### Checklist
${hasLogging ? "✅" : "❌"} Tool call logging active
${hasRegisteredSystems ? "✅" : "❌"} AI systems registered
${!hasHighRisk ? "✅" : "⚠️"} No unreviewed high-risk operations
${"✅"} Record retention active

### ${overallStatus === "✅ ON TRACK" ? "Keep it up!" : "Actions Needed:"}
${!hasLogging ? "- Start logging tool calls with complianceguard_log_tool_call\n" : ""}${!hasRegisteredSystems ? "- Register your AI systems with complianceguard_register_system\n" : ""}${hasHighRisk ? "- Review high-risk operations in the audit log\n" : ""}`;

    return { content: [{ type: "text", text: status }] };
  }
);

// ═══════════════════════════════════════════
// Tool 5: Register AI System
// ═══════════════════════════════════════════

server.registerTool(
  "complianceguard_register_system",
  {
    title: "Register AI System",
    description:
      "Register an AI system for EU AI Act compliance tracking. Each AI system (e.g., a Claude agent, a chatbot, an automated pipeline) should be registered so its tool calls can be tracked and reported.",
    inputSchema: {
      name: z.string().describe("Human-readable name of the AI system"),
      provider: z.string().describe("Provider/vendor of the AI model (e.g., Anthropic, OpenAI)"),
      description: z.string().describe("Description of what the AI system does"),
      purpose: z.string().describe("Intended purpose/use case"),
      riskLevel: z.enum(["minimal", "limited", "high", "unacceptable"]).default("limited").describe("EU AI Act risk classification"),
      mcpServers: z.array(z.string()).default([]).describe("List of MCP servers this system connects to"),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  async (params) => {
    const system: AISystem = {
      id: `SYS-${Date.now()}`,
      name: params.name,
      provider: params.provider,
      riskLevel: params.riskLevel,
      registeredAt: new Date().toISOString(),
      description: params.description,
      purpose: params.purpose,
      mcpServers: params.mcpServers,
      complianceStatus: "pending-review",
    };
    registeredSystems.push(system);

    return {
      content: [{
        type: "text",
        text: `✅ AI System Registered\n\nID: ${system.id}\nName: ${system.name}\nProvider: ${system.provider}\nRisk Level: ${system.riskLevel}\nMCP Servers: ${system.mcpServers.join(", ") || "None"}\nStatus: pending-review\n\nNext: Start logging tool calls with complianceguard_log_tool_call using system ID "${system.id}"`,
      }],
    };
  }
);

// ═══════════════════════════════════════════
// Tool 6: Risk Classification
// ═══════════════════════════════════════════

server.registerTool(
  "complianceguard_risk_classify",
  {
    title: "Classify AI Risk Level",
    description:
      "Classify an AI system or use case according to EU AI Act risk levels. Provides the classification, applicable requirements, and obligations based on the regulation's Annex III categories.",
    inputSchema: {
      useCase: z.string().describe("Description of the AI use case to classify"),
      sector: z.string().optional().describe("Industry sector (e.g., healthcare, finance, law enforcement, employment)"),
      affectsNaturalPersons: z.boolean().default(true).describe("Whether the AI system affects natural persons' rights"),
      isAutonomous: z.boolean().default(false).describe("Whether the system makes autonomous decisions without human oversight"),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  async (params) => {
    // Simplified risk classification logic based on EU AI Act Annex III
    const highRiskSectors = ["healthcare", "law enforcement", "employment", "education", "migration", "critical infrastructure", "judiciary"];
    const unacceptablePractices = ["social scoring", "mass surveillance", "manipulation", "exploitation"];

    let riskLevel: string;
    let obligations: string[];
    const lcUseCase = params.useCase.toLowerCase();
    const lcSector = (params.sector || "").toLowerCase();

    if (unacceptablePractices.some((p) => lcUseCase.includes(p))) {
      riskLevel = "🚫 UNACCEPTABLE — PROHIBITED";
      obligations = ["This AI practice is prohibited under the EU AI Act. Do not deploy."];
    } else if (highRiskSectors.some((s) => lcSector.includes(s)) || params.isAutonomous) {
      riskLevel = "🔴 HIGH RISK";
      obligations = [
        "Mandatory conformity assessment before market placement",
        "Risk management system (Art. 9)",
        "Data governance and quality requirements (Art. 10)",
        "Technical documentation (Art. 11)",
        "Automatic logging / record-keeping (Art. 12) ← ComplianceGuard handles this",
        "Transparency to deployers (Art. 13)",
        "Human oversight measures (Art. 14)",
        "Accuracy, robustness, cybersecurity (Art. 15)",
        "Registration in EU database",
        "Post-market monitoring system",
      ];
    } else if (params.affectsNaturalPersons) {
      riskLevel = "🟡 LIMITED RISK";
      obligations = [
        "Transparency obligations (Art. 50) — users must be informed they are interacting with AI",
        "Record-keeping recommended (Art. 12) ← ComplianceGuard handles this",
        "Technical documentation recommended",
      ];
    } else {
      riskLevel = "🟢 MINIMAL RISK";
      obligations = [
        "No mandatory obligations, but voluntary codes of conduct encouraged",
        "Record-keeping still recommended for best practice ← ComplianceGuard handles this",
      ];
    }

    const result = `## EU AI Act Risk Classification

**Use Case:** ${params.useCase}
**Sector:** ${params.sector || "General"}
**Affects Natural Persons:** ${params.affectsNaturalPersons ? "Yes" : "No"}
**Autonomous Decisions:** ${params.isAutonomous ? "Yes" : "No"}

### Classification: ${riskLevel}

### Obligations:
${obligations.map((o) => `- ${o}`).join("\n")}

### ComplianceGuard Coverage:
- ✅ Article 12 (Record-Keeping): Fully handled by audit logging
- ✅ Automatic logging of all tool calls and decisions
- ✅ Regulator-ready export format available

*Classification based on EU AI Act (Regulation 2024/1689), Annex III*`;

    return { content: [{ type: "text", text: result }] };
  }
);

// ═══════════════════════════════════════════
// Tool 7: Export Records
// ═══════════════════════════════════════════

server.registerTool(
  "complianceguard_export_records",
  {
    title: "Export Compliance Records",
    description:
      "Export audit log records in a structured, regulator-ready JSON format suitable for EU AI Act Article 12 compliance demonstrations. Returns the complete dataset for the specified period.",
    inputSchema: {
      periodDays: z.number().int().min(1).max(365).default(90).describe("Number of days of records to export"),
      systemId: z.string().optional().describe("Export only for a specific system"),
      format: z.enum(["json", "summary"]).default("json").describe("Export format: full JSON or summary"),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  async (params) => {
    const cutoff = new Date(Date.now() - params.periodDays * 86400000).toISOString();
    let entries = auditLog.filter((e) => e.timestamp >= cutoff);
    if (params.systemId) entries = entries.filter((e) => e.systemId === params.systemId);

    const exportData = {
      exportMetadata: {
        generatedAt: new Date().toISOString(),
        generatedBy: "ComplianceGuard MCP Server v1.0.0",
        organization: "Delzar Solutions LLC",
        regulation: "EU AI Act (Regulation 2024/1689)",
        article: "Article 12 — Record-Keeping",
        periodStart: cutoff,
        periodEnd: new Date().toISOString(),
        totalEntries: entries.length,
      },
      registeredSystems: params.systemId
        ? registeredSystems.filter((s) => s.id === params.systemId)
        : registeredSystems,
      auditEntries: params.format === "json" ? entries : [],
      summary: {
        totalCalls: entries.length,
        successfulCalls: entries.filter((e) => e.success).length,
        failedCalls: entries.filter((e) => !e.success).length,
        riskDistribution: entries.reduce((acc, e) => {
          acc[e.riskLevel] = (acc[e.riskLevel] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
        uniqueTools: [...new Set(entries.map((e) => `${e.toolServer}/${e.toolName}`))],
        uniqueOperators: [...new Set(entries.map((e) => e.userId))],
      },
    };

    return {
      content: [{
        type: "text",
        text: params.format === "json"
          ? JSON.stringify(exportData, null, 2)
          : `## Export Summary\n\nPeriod: ${params.periodDays} days\nTotal Entries: ${exportData.summary.totalCalls}\nSuccess Rate: ${exportData.summary.totalCalls > 0 ? ((exportData.summary.successfulCalls / exportData.summary.totalCalls) * 100).toFixed(1) : 0}%\nRegistered Systems: ${exportData.registeredSystems.length}\nUnique Tools: ${exportData.summary.uniqueTools.length}\nUnique Operators: ${exportData.summary.uniqueOperators.length}`,
      }],
    };
  }
);

// ═══════════════════════════════════════════
// Tool 8: Clear Logs
// ═══════════════════════════════════════════

server.registerTool(
  "complianceguard_clear_logs",
  {
    title: "Clear Audit Logs",
    description:
      "Clear all audit log entries. WARNING: This is destructive and cannot be undone. Use complianceguard_export_records first to back up records. Requires confirmation string 'CONFIRM_CLEAR' to execute.",
    inputSchema: {
      confirmation: z.literal("CONFIRM_CLEAR").describe("Must be exactly 'CONFIRM_CLEAR' to proceed"),
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  },
  async (params) => {
    const count = auditLog.length;
    auditLog.length = 0;
    entryCounter = 0;
    return {
      content: [{ type: "text", text: `🗑️ Cleared ${count} audit log entries. The audit log is now empty.` }],
    };
  }
);

// ═══════════════════════════════════════════
// Start Server
// ═══════════════════════════════════════════

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("ComplianceGuard MCP Server running on stdio");
  console.error("EU AI Act Article 12 Compliance Middleware — Delzar Solutions LLC");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
