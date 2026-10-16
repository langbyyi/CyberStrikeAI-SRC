const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');
const monitor = fs.readFileSync('web/static/js/monitor.js', 'utf8');
const template = fs.readFileSync('web/templates/index.html', 'utf8');
const rbacGuards = fs.readFileSync('web/static/js/rbac-guards.js', 'utf8');

// 取某函数的完整源码：切到下一个函数声明（不依赖下一个符号恰好是函数）
function bodyOf(source, name) {
    const start = source.indexOf(`function ${name}(`);
    assert.notEqual(start, -1, `${name} should exist`);
    const candidates = [
        source.indexOf('\nfunction ', start + 1),
        source.indexOf('\nasync function ', start + 1),
    ].filter((i) => i !== -1);
    const end = candidates.length ? Math.min(...candidates) : source.length;
    return source.slice(start, end);
}

// 「停止任务」与「单次工具终止」都必须直接生效：旧版超集弹窗不允许复活。
test('旧「中断并继续」超集弹窗已彻底移除', () => {
    assert.doesNotMatch(template, /user-interrupt-modal/, '模板不应再有该弹窗');
    assert.doesNotMatch(template, /submitUserInterruptContinue|submitUserInterruptHardCancel/);
    assert.doesNotMatch(monitor, /openUserInterruptModal|closeUserInterruptModal|submitUserInterrupt|userInterruptModalPending/);
    assert.doesNotMatch(chat, /openUserInterruptModal|__monitorInterruptContext/);
    assert.doesNotMatch(rbacGuards, /submitUserInterrupt/);
});

test('停止任务直接取消，不弹窗', () => {
    const cancel = bodyOf(monitor, 'cancelActiveTask');
    assert.match(cancel, /performHardCancelProgressTask\(findProgressIdByConversationId\(target\), target\)/);
    assert.doesNotMatch(cancel, /openUserInterruptModal/);
});

// 单次工具终止只走一条后端路径：/api/monitor/execution/:id/cancel（它自己反查会话，
// 并带仅凭 executionId 的内/外部 MCP 兜底），不再分叉到 /api/agent-loop/cancel{continueAfter}。
test('单次工具终止只有一条后端路径', () => {
    const submit = bodyOf(chat, 'cancelMCPToolExecutionSubmit');
    assert.match(submit, /\/api\/monitor\/execution\/\$\{encodeURIComponent\(executionId\)\}\/cancel/);
    assert.match(submit, /note: userNote \|\| ''/);
    assert.doesNotMatch(submit, /apiFetch\(\s*['"`]\/api\/agent-loop\/cancel/, '不得再调 agent-loop 的 continueAfter 分支');
    assert.doesNotMatch(submit, /requestCancelWithContinue/);
    assert.doesNotMatch(monitor, /requestCancelWithContinue/, '旧的 continueAfter 前端封装应已删除');
});

test('监控页「终止」统一打开专用弹窗并把 executionId 交给它', () => {
    const terminate = bodyOf(chat, 'cancelMCPToolExecution');
    assert.match(terminate, /openMcpToolAbortModal\(executionId, options\)/);
    assert.doesNotMatch(terminate, /openUserInterruptModal|monitorState\.executions/);
});
