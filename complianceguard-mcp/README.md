# ComplianceGuard MCP Server

**EU AI Act Article 12 compliance audit-logging middleware for MCP servers.**

Built by [Delzar Solutions LLC](https://delzarsolutionsllc.com) — Cherokee Nation Citizen-Owned

## What It Does

ComplianceGuard sits alongside your MCP servers and provides automatic audit logging for EU AI Act compliance. Every tool call across all connected MCP servers can be logged, tracked, and reported in a regulator-ready format.

**EU AI Act Enforcement Deadline: August 2, 2026**

95% of the 20,000+ MCP servers in existence are completely unprepared for Article 12 record-keeping obligations. ComplianceGuard solves this.

## Tools (8)

| Tool | Description |
|------|-------------|
| `complianceguard_log_tool_call` | Log an MCP tool invocation for Article 12 compliance |
| `complianceguard_get_audit_log` | Retrieve audit log entries with filtering & pagination |
| `complianceguard_compliance_report` | Generate full EU AI Act compliance report |
| `complianceguard_check_status` | Quick compliance status check with gap analysis |
| `complianceguard_register_system` | Register an AI system for tracking |
| `complianceguard_risk_classify` | Classify AI use case risk level per EU AI Act |
| `complianceguard_export_records` | Export records in regulator-ready JSON format |
| `complianceguard_clear_logs` | Clear audit logs (with confirmation safeguard) |

## Quick Start

```bash
# Install
npm install -g complianceguard-mcp-server

# Or run directly
npx complianceguard-mcp-server
```

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "complianceguard": {
      "command": "npx",
      "args": ["-y", "complianceguard-mcp-server"]
    }
  }
}
```

## Pricing

- **Free Tier**: 5 tool calls/day — perfect for testing
- **Pro Tier**: $19/month — unlimited logging, full reports, export

## License

MIT

---

*Built with the FORGE Protocol by Delzar Solutions LLC*
*Cherokee Nation Citizen-Owned | EU AI Act Compliance Middleware*
