(function (root, factory) {
    const model = factory();
    if (typeof module === 'object' && module.exports) module.exports = model;
    if (root) root.ApprovalUIModel = model;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    function text(value) {
        return typeof value === 'string' ? value.trim() : '';
    }

    function pendingCount(page) {
        if (page && typeof page.total === 'number' && Number.isFinite(page.total) && page.total >= 0) {
            return page.total;
        }
        return page && Array.isArray(page.items) ? page.items.length : 0;
    }

    function buildApprovalQuery(filters) {
        const input = filters && typeof filters === 'object' ? filters : {};
        const query = new URLSearchParams();
        const status = text(input.status);
        if (status) query.set('status', status);
        if (typeof input.terminal === 'boolean') query.set('terminal', String(input.terminal));
        for (const name of ['q', 'decision', 'actorType']) {
            const value = text(input[name]);
            if (value) query.set(name, value);
        }
        if (Number.isInteger(input.limit) && input.limit >= 1 && input.limit <= 200) {
            query.set('limit', String(input.limit));
        }
        if (Number.isInteger(input.offset) && input.offset >= 0) query.set('offset', String(input.offset));
        return query.toString();
    }

    function createLatestRequestGate() {
        let latestSequence = 0;
        return {
            begin: function (queryKey) {
                latestSequence += 1;
                return { sequence: latestSequence, queryKey: String(queryKey || '') };
            },
            // 只比对发起序号：响应属于发起它的那次请求。输入框后来的
            // 变化只有在触发新请求（新的 begin）后才使旧响应失效。
            isCurrent: function (token) {
                return !!token && token.sequence === latestSequence;
            }
        };
    }

    function decisionTime(decision) {
        const timestamp = Date.parse(decision && decision.createdAt);
        return Number.isFinite(timestamp) ? timestamp : Number.POSITIVE_INFINITY;
    }

    function toAuditView(request) {
        const source = request && typeof request === 'object' ? request : {};
        const decisions = Array.isArray(source.decisions) ? source.decisions.slice() : [];
        decisions.sort(function (left, right) {
            return decisionTime(left) - decisionTime(right);
        });
        let reviewDecision = '';
        for (let index = decisions.length - 1; index >= 0; index -= 1) {
            const value = text(decisions[index] && decisions[index].decision).toLowerCase();
            if (value) {
                reviewDecision = value;
                break;
            }
        }
        return {
            request: request,
            decisions: decisions,
            reviewDecision: reviewDecision,
            executionStatus: text(source.status),
			matchedPolicies: Array.isArray(source.matchedPolicies) ? source.matchedPolicies.slice() : [],
            executionSummary: text(source.executionSummary)
        };
    }

    // 规则只读详情视图：规则对象由 /api/approval-rules 直接返回（无包装层）。
    function toRuleView(item) {
        const rule = item && typeof item === 'object' ? item : {};
        let matcherJson = '';
        if (rule.matcher && typeof rule.matcher === 'object') {
            try { matcherJson = JSON.stringify(rule.matcher, null, 2); } catch (e) { matcherJson = ''; }
        }
        return {
            id: rule.id || '',
            enabled: rule.enabled !== false,
            priority: Number(rule.priority || 0),
            riskLevel: rule.riskLevel || '',
            matcherJson: matcherJson
        };
    }

    return {
        pendingCount: pendingCount,
        buildApprovalQuery: buildApprovalQuery,
        createLatestRequestGate: createLatestRequestGate,
        toAuditView: toAuditView,
        toRuleView: toRuleView
    };
}));
