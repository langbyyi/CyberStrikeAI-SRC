const test = require('node:test');
const assert = require('node:assert/strict');

const ApprovalUIModel = require('../static/js/approval-ui-model.js');

test('pendingCount trusts a complete server total and otherwise uses loaded items', () => {
    assert.equal(ApprovalUIModel.pendingCount({ total: 237, items: Array(200) }), 237);
    assert.equal(ApprovalUIModel.pendingCount({ items: [1, 2] }), 2);
    assert.equal(ApprovalUIModel.pendingCount({ total: -1, items: [1, 2] }), 2);
    assert.equal(ApprovalUIModel.pendingCount({ total: Number.NaN, items: [1, 2, 3] }), 3);
    assert.equal(ApprovalUIModel.pendingCount({ total: '237', items: [1] }), 1);
});

test('approval queries include only meaningful supported parameters with URL encoding', () => {
    assert.equal(
        ApprovalUIModel.buildApprovalQuery({
            status: ' pending human ', terminal: false, q: 'risk & review', decision: 'approve',
            actorType: 'agent', limit: 50, offset: 0, projectId: 'must-not-leak', ignored: 'nope'
        }),
        'status=pending+human&terminal=false&q=risk+%26+review&decision=approve&actorType=agent&limit=50&offset=0'
    );
    assert.equal(ApprovalUIModel.buildApprovalQuery({ status: '', q: ' ', limit: -1, offset: Number.NaN }), '');
    assert.equal(ApprovalUIModel.buildApprovalQuery({ limit: 1.5, offset: 0.5 }), '');
});

test('latest request gate drops an older response that resolves after a newer request', async () => {
    const gate = ApprovalUIModel.createLatestRequestGate();
    let resolveOlder;
    let resolveNewer;
    const older = new Promise((resolve) => { resolveOlder = resolve; });
    const newer = new Promise((resolve) => { resolveNewer = resolve; });
    let currentQueryKey = 'status=pending_human&q=older&limit=20&offset=0';
    const applied = [];

    async function applyWhenCurrent(promise, token) {
        const value = await promise;
        if (gate.isCurrent(token, currentQueryKey)) applied.push(value);
    }

    const olderToken = gate.begin(currentQueryKey);
    const olderRun = applyWhenCurrent(older, olderToken);
    currentQueryKey = 'status=pending_human&q=newer&limit=20&offset=0';
    const newerToken = gate.begin(currentQueryKey);
    const newerRun = applyWhenCurrent(newer, newerToken);

    resolveNewer('newer');
    await newerRun;
    resolveOlder('older');
    await olderRun;

    assert.deepEqual(applied, ['newer']);
});

test('audit view separates review decision from failed execution and preserves request evidence', () => {
    const request = {
        status: 'failed', executionSummary: 'tool exited 1', matchedPolicies: ['danger.exec'],
        decisions: [{ decision: 'approve', actorType: 'human', createdAt: '2026-08-28T10:00:00Z' }]
    };

    const view = ApprovalUIModel.toAuditView(request);

    assert.equal(view.request, request);
    assert.equal(view.reviewDecision, 'approve');
    assert.equal(view.executionStatus, 'failed');
    assert.deepEqual(view.matchedPolicies, ['danger.exec']);
    assert.equal(view.executionSummary, 'tool exited 1');
});

test('audit view never invents a reject for expired or cancelled requests without decisions', () => {
    for (const status of ['expired', 'cancelled']) {
        const view = ApprovalUIModel.toAuditView({ status, decisions: [] });
        assert.equal(view.reviewDecision, '');
        assert.equal(view.executionStatus, status);
    }
});

test('audit view orders the decision chain chronologically and uses its final real decision', () => {
    const view = ApprovalUIModel.toAuditView({
        status: 'succeeded',
        decisions: [
            { decision: 'approve', createdAt: '2026-08-28T10:02:00Z' },
            { decision: 'escalate', createdAt: '2026-08-28T10:01:00Z' },
            { decision: '', createdAt: '2026-08-28T10:03:00Z' }
        ]
    });

    assert.deepEqual(view.decisions.map((item) => item.decision), ['escalate', 'approve', '']);
    assert.equal(view.reviewDecision, 'approve');
});

test('latest request gate keeps an in-flight response when the search input changes without a new request', () => {
    const gate = ApprovalUIModel.createLatestRequestGate();
    const token = gate.begin('status=pending_human&q=foo&limit=20&offset=0');

    // 用户在请求进行中改了搜索框但没有回车：没有新请求开始，
    // 响应仍属于当前请求，不得被丢弃（否则列表停在 Loading）。
    assert.equal(gate.isCurrent(token), true);

    const newer = gate.begin('status=pending_human&q=&limit=20&offset=0');
    assert.equal(gate.isCurrent(token), false);
    assert.equal(gate.isCurrent(newer), true);
});

test('toRuleView normalizes a rule object returned directly by the API', () => {
    const view = ApprovalUIModel.toRuleView({
        id: 'danger.exec', revision: 3, enabled: true,
        priority: 900, riskLevel: 'high',
        matcher: { tools: ['exec'], textPatterns: ['rm -rf'] }
    });

    assert.equal(view.id, 'danger.exec');
    assert.equal(view.enabled, true);
    assert.equal(view.priority, 900);
    assert.deepEqual(JSON.parse(view.matcherJson), { tools: ['exec'], textPatterns: ['rm -rf'] });
    assert.equal(Object.hasOwn(view, 'locked'), false);
    assert.equal(Object.hasOwn(view, 'builtin'), false);
    assert.equal(Object.hasOwn(view, 'revision'), false);

    const empty = ApprovalUIModel.toRuleView(null);
    assert.equal(empty.id, '');
    assert.equal(empty.priority, 0);
    assert.equal(empty.enabled, true);
    assert.equal(empty.matcherJson, '');
});
