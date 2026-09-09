# Tool call blocking

The **Security** sidebar groups the existing **Human in the loop** page with **Call blocking**. Call blocking checks internal MCP tools, external MCP tools, and HTTP MCP calls immediately before execution, independently of HITL approvals and allowlists.

The standalone `cmd/mcp-stdio` service also loads these rules. As a separate process, it requires a restart to pick up settings saved by the web application.

Government-domain protection is enabled by default, including when an older config omits `tool_guard`. The default rule matches government-domain forms such as `.gov`, `.gov.cn`, and wildcards, ignoring case. Add, edit, enable, or delete rules on the new page. Test an unsaved configuration with a tool name and JSON arguments before saving; testing never executes tools or updates the active policy.

**Add rule** opens a dialog with an independent draft and its own test inputs and results. **Add to list** checks the rule's RE2 syntax before adding it to the page draft; canceling leaves the list unchanged. Use the page's save button to apply the added rule.

Use **Test all rules** in the page header to check the configured order and enabled states. **Test this rule** inside an expanded rule opens a test area directly below that editor. Single-rule tests ignore the global and individual enable switches so disabled drafts can be checked; other rules cannot claim the match first. Each test area keeps separate inputs and displays its own matched text and rendered reminder.

Saving validates every rule, including disabled rules, writes only the `tool_guard` YAML section, and applies the policy immediately. Validation or write failure preserves the existing protection. Manual YAML edits require a restart; a non-null `tool_guard` section must explicitly provide `enabled` and `rules` (use `[]` for no rules). The first matching enabled rule supplies the reminder. Rules use Go/RE2 syntax; lookarounds and backreferences are unsupported. Up to 100 rules are allowed, with patterns and reminder templates capped at 4096 bytes each.

Reminder placeholders are `{match}` (matched text), `{tool}` (tool name), and `{rule}` (rule name). An optional named group `(?P<match>...)` selects the matched text. Empty templates use a default reminder.

Checks inspect the tool name, serialized JSON, nested strings and keys, and up to three rounds of common URL percent decoding. Blocked calls use a separate **Blocked** status in the UI and execution records, with the reason preserved. Monitoring counts blocks separately and excludes them from failed calls and the success-rate denominator. At startup after an upgrade, clearly identifiable legacy guard-block records are migrated to this status. MCP results retain `isError: true` alongside `blocked: true` so the agent knows the request did not execute. External MCP policy blocks do not count as provider failures for circuit breaking. Updated rules cannot cancel calls already dispatched.

Viewing and testing require `config:read`. Saving requires `config:write` with global scope, and configuration changes are audited. HITL approvals, edited arguments, and approval allowlists cannot bypass the execution check.

Text matching cannot establish target ownership from IP addresses, DNS aliases, redirects, file contents, or arbitrary obfuscation. Independent execution paths such as direct terminals and optional agent local tools are outside the MCP guard. Benign references to a protected domain in parameter text may also be blocked. Retain HITL and maintain rules against the actual authorized scope.

API endpoints:

- `GET /api/tool-guard`: active `{enabled, rules}` configuration.
- `PUT /api/tool-guard`: save that structure, explicitly providing both fields. Rules contain `id`, `name`, `enabled`, `pattern`, and `message`.
- `POST /api/tool-guard/test`: accepts `{config, toolName, arguments}` and returns `{blocked, match?}`. Match fields are `ruleId`, `ruleName`, `matchedText`, and `message`.
