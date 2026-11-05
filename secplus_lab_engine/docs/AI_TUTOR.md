# AI tutor (MCP server)

`python main.py mcp` starts an [MCP](https://modelcontextprotocol.io) server over stdio. It lets an AI assistant use this course's engines and question bank to quiz you, explain a lab, or plan your study day. It uses only the standard library, needs no API keys, and nothing leaves your computer except what your MCP client itself sends.

## Connect it

**Claude Code:**

```bash
claude mcp add identityops -- python /full/path/to/secplus_lab_engine/main.py mcp
```

**Claude Desktop** (Settings → Developer → Edit config, then restart):

```json
{
  "mcpServers": {
    "identityops": {
      "command": "python",
      "args": ["/full/path/to/secplus_lab_engine/main.py", "mcp"]
    }
  }
}
```

Then try one of these:
- "Quiz me on objective 2.4, one concept at a time."
- "Plan 30 minutes of study from my progress."
- "Walk me through Lab 25 like a senior colleague."

The three built-in prompts (`quiz_me`, `plan_my_day`, `explain_lab`) do the same.

To let the tutor **save** your answers to your progress (daily review, quiz scores), start it with the write scope:

```bash
python main.py mcp --grant progress:write
```

## Tools

| Scope | Tool | What it does |
|---|---|---|
| read | `course_overview` | Exam countdown, domains, every objective with its topics, quizzes and labs |
| read | `get_lesson` | A lab's lesson, key concepts, exam tips and work ticket |
| read | `run_lab` | Runs a lab's engine (sample or seeded random scenario) and returns its report |
| read | `case_study` | Portfolio case study (Markdown) from a lab's real results |
| read | `list_quizzes` | An objective's concept quizzes and mixed sets, with your best scores |
| read | `progress_summary` | Weakest objectives, reviews due today, streak |
| quiz | `start_quiz` | A quiz's questions **without answers** |
| quiz | `daily_review` | Today's spaced-repetition questions, without answers |
| quiz | `check_answer` | Right or wrong, the correct answer and the explanation |
| progress:write | `record_answer`, `record_quiz` | Save results (off unless granted) |

## Security model (an identity and authorization showcase)

The server is built like a small policy enforcement point:

- **Deny by default.** `config/mcp_policy.json` lists every tool under exactly one scope, and the server refuses to start if the policy's default is not `deny`. Unlisted tools do not exist.
  - Granted scopes default to `read` and `quiz`. `progress:write` must be granted explicitly.
  - Tools in scopes that aren't granted are not even listed to the client.
- **Least privilege for the AI.** Quiz tools return questions without answers or explanations. The answer comes back only through `check_answer`, so the assistant has to quiz rather than reveal.
- **Input validation before any engine runs.** Each tool has a JSON schema (types, ranges, patterns, enums, no unknown fields). For example, `"lab": "1; rm -rf /"` is rejected as "must be integer".
- **Audit trail.** Every call, allowed, denied or failed, is appended to `mcp_audit.jsonl` (git-ignored). Each line records the time, tool, scope, decision and reason, and the argument *names* only, never their values. That is the record a PEP would send to a SIEM.
- **No network, no secrets.** The server reads local files and writes only your progress (when granted) and the audit log.

Interview talking point: "I built an MCP server for my study platform with deny-by-default, scope-based authorization, schema validation and an audit log. The AI agent gets least privilege: it can quiz me but never sees the answer key until I respond."

Tests: `tests/test_mcp_server.py` covers the protocol, the authorization decisions, validation, audit records, every tool and the stdio transport. The server also works with the official MCP Python SDK client.
