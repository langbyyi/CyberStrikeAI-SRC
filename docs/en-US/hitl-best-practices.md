# Human-in-the-loop (HITL) Best Practices

[中文](../zh-CN/hitl-best-practices.md)

HITL reviews tool calls before an Agent executes them. Use it to control high-risk operations, keep an audit trail, and let an Audit Agent take over routine approvals when human reviewers cannot keep up.

## Where To Configure

Open **System Settings → Human-in-the-loop** in the web UI. You can configure:

- Global default reviewer: `human` or `audit_agent`
- Dedicated Audit Agent model: `hitl.audit_model`
- Resolved audit log retention days
- No-approval tool allowlist: `hitl.tool_whitelist`
- Audit prompts for approval mode and review-edit mode

Example `config.yaml`:

```yaml
hitl:
  default_reviewer: human
  audit_model:
    provider: ""
    base_url: ""
    api_key: ""
    model: "" # set a small model here; blank reuses the default AI channel model
  retention_days: 90
  tool_whitelist: [read_file, list_dir, glob, grep, tool_search]
```

`audit_model` supports partial configuration. Empty fields inherit from the resolved default AI channel, so the common setup is to fill only `model` and run approvals on a cheaper small model.

## Recommended Approval Strategy

### 1. Start With Humans, Then Delegate Gradually

At the beginning, prefer:

- `default_reviewer: human`
- Only clearly read-only tools in `tool_whitelist`
- Human approval for file writes, command execution, C2 tasks, and WebShell operations

After observing audit logs, move repeated low-risk operations into the allowlist.

### 2. Use A Small Model When Humans Cannot Keep Up

When pending approvals start piling up, switch routine review to the Audit Agent:

```yaml
hitl:
  default_reviewer: audit_agent
  audit_model:
    model: "your-small-reviewer-model"
```

Good candidates for small-model review:

- Read-only queries
- Reconnaissance
- Port and service scans
- Directory enumeration
- Non-destructive validation commands

Keep human review for:

- Deleting, overwriting, or clearing data
- Modifying permissions, passwords, or accounts
- Persistence, lateral movement, and high-risk C2 tasks
- Writes against production targets

### 3. Encode Your Policy In The Prompt

The Audit Agent prompt should describe an operational policy, not just say “be careful.” Make it explicit:

- Which low-risk actions are normally approved
- Which destructive actions must be rejected
- Which cases require escalation to a human
- How review-edit mode may narrow arguments

Example policy snippet:

```text
Approve routine reconnaissance, read-only queries, and port scans by default.
Reject file deletion, database clearing, account or permission changes, persistence, and stopping critical services.
Reject actions outside the user-authorized target scope.
In review-edit mode, you may narrow paths, targets, or command arguments before approving, but must not expand the attack surface.
```

### 4. Keep The Allowlist Conservative

Allowlisted tools skip approval, so keep the list stable and low-risk. Recommended examples:

- `read_file`
- `list_dir`
- `glob`
- `grep`
- `tool_search`

Avoid globally allowlisting:

- Arbitrary shell execution tools
- File write/delete tools
- C2 task tools
- WebShell command execution tools

## Mode Selection

| Mode | Best for |
|------|----------|
| Off | Local labs or fully trusted toolchains |
| Approval | Approve/reject only |
| Review-edit | Let the Audit Agent narrow arguments before approval |

If you configured a small audit model, start with **Approval** mode. Use **Review-edit** only when you want the AI to safely narrow paths, target ranges, or command arguments.

## Operations Tips

- Review **Human-in-the-loop → Audit logs** regularly and tune allowlists/prompts.
- In high-risk environments, keep `default_reviewer: human` and use the Audit Agent only for recommendations.
- If the small-model reviewer fails, CyberStrikeAI rejects conservatively by default.
- After changing `hitl.audit_model`, click **Test audit model** in the settings page.
- For production, customer, or real business systems, keep a human as the final approver.
