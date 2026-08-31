'use strict';

const ApprovalUIModel = window.ApprovalUIModel;
const APPROVAL_LOGS_PAGE_SIZE_KEY = 'cyberstrike_hitl_logs_page_size';
const APPROVAL_PENDING_PAGE_SIZE_KEY = 'cyberstrike_hitl_pending_page_size';
const APPROVAL_PAGE_SIZE_OPTIONS = [10, 20, 50, 100];

let approvalPolicyLoadSequence = 0;
let approvalRulesCache = [];
let hitlActiveTab = 'pending';
let hitlLogsPage = 1;
let hitlLogsPageSize = 20;
let hitlLogsTotal = 0;
let hitlLogsCache = [];
let hitlLogsLoaded = false;
const auditRequestGate = ApprovalUIModel.createLatestRequestGate();
let hitlPendingPage = 1;
let hitlPendingPageSize = 20;
let hitlPendingTotal = 0;
let hitlPendingCache = [];
let hitlPendingLoaded = false;
const pendingRequestGate = ApprovalUIModel.createLatestRequestGate();

// 供任务轮询与项目树 reconcile 使用。maxPages 是硬上限：该加载器挂在
// 2 秒任务轮询上，pending 异常堆积时每轮请求数必须有界（默认 5 页
// 1000 条）；正常规模下行为与无界循环一致。
async function fetchAllPendingApprovals(apiFetch, pageSize = 200, maxPages = 5) {
    const requestedSize = Number(pageSize);
    const limit = Math.min(200, Math.max(1, Number.isFinite(requestedSize) ? Math.floor(requestedSize) : 200));
    const requestedPages = Number(maxPages);
    const pageCap = Math.max(1, Number.isFinite(requestedPages) ? Math.floor(requestedPages) : 5);
    const items = [];
    let offset = 0;
    let total = null;
    let fetchedPages = 0;
    while (fetchedPages < pageCap) {
        fetchedPages += 1;
        const query = ApprovalUIModel.buildApprovalQuery({
            status: 'pending_human',
            limit: limit,
            offset: offset
        });
        const response = await apiFetch('/api/approvals?' + query);
        if (!response || !response.ok) throw new Error('Failed to load pending approvals');
        const page = await response.json();
        const pageItems = Array.isArray(page && page.items) ? page.items : [];
        items.push.apply(items, pageItems);
        offset += pageItems.length;
        if (total === null) total = ApprovalUIModel.pendingCount(page);
        if (pageItems.length === 0 || offset >= total) return items;
    }
    return items;
}

function approvalLocale() {
    if (typeof window.__locale === 'string' && window.__locale.length) {
        return window.__locale.startsWith('zh') ? 'zh-CN' : 'en-US';
    }
    return (typeof navigator !== 'undefined' && navigator.language) ? navigator.language : 'en-US';
}

function approvalFormatTime(value) {
    if (!value) return hitlT('notAvailable', 'Not available');
    try {
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        return date.toLocaleString(approvalLocale(), {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
        });
    } catch (e) {
        return String(value);
    }
}

function approvalPaginationT(key, params, fallback) {
    if (typeof window.t === 'function') {
        const keys = (key === 'paginationInfo' || key === 'perPageLabel')
            ? ['mcpMonitor.' + key, 'mcp.' + key]
            : ['mcp.' + key];
        for (let index = 0; index < keys.length; index += 1) {
            const translated = window.t(keys[index], params || {});
            if (typeof translated === 'string' && translated && translated !== keys[index]) return translated;
        }
    }
    return fallback != null ? fallback : key;
}

function initApprovalPageSize(storageKey, fallbackSize, assign) {
    try {
        const saved = parseInt(localStorage.getItem(storageKey), 10);
        if (APPROVAL_PAGE_SIZE_OPTIONS.indexOf(saved) >= 0) {
            assign(saved);
            return;
        }
    } catch (e) { /* ignore unavailable storage */ }
    assign(fallbackSize);
}

function renderApprovalPagination(containerId, state, goPageName, pageSizeChangeName, selectId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const total = state.total || 0;
    const currentPage = state.page || 1;
    const pageSize = state.pageSize || 20;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const start = total === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = total === 0 ? 0 : Math.min(currentPage * pageSize, total);
    const infoText = approvalPaginationT('paginationInfo', { start: start, end: end, total: total },
        'Showing ' + start + '-' + end + ' of ' + total);
    const perPageLabel = approvalPaginationT('perPageLabel', null, 'Per page');
    const firstPageLabel = approvalPaginationT('firstPage', null, 'First');
    const prevPageLabel = approvalPaginationT('prevPage', null, 'Previous');
    const pageInfoText = approvalPaginationT('pageInfo', { page: currentPage, total: totalPages },
        'Page ' + currentPage + ' of ' + totalPages);
    const nextPageLabel = approvalPaginationT('nextPage', null, 'Next');
    const lastPageLabel = approvalPaginationT('lastPage', null, 'Last');
    const disableFirst = currentPage === 1 || total === 0;
    const disableLast = currentPage >= totalPages || total === 0;
    let html = '<div class="monitor-pagination"><div class="pagination-info">';
    html += '<span>' + escapeHtml(infoText) + '</span>';
    html += '<label class="pagination-page-size">' + escapeHtml(perPageLabel);
    html += '<select id="' + escapeHtml(selectId) + '" onchange="' + escapeHtml(pageSizeChangeName) + '()">';
    APPROVAL_PAGE_SIZE_OPTIONS.forEach(function (size) {
        html += '<option value="' + size + '"' + (pageSize === size ? ' selected' : '') + '>' + size + '</option>';
    });
    html += '</select></label></div><div class="pagination-controls">';
    html += '<button type="button" class="btn-secondary" onclick="' + escapeHtml(goPageName) + '(1)"' + (disableFirst ? ' disabled' : '') + '>' + escapeHtml(firstPageLabel) + '</button>';
    html += '<button type="button" class="btn-secondary" onclick="' + escapeHtml(goPageName) + '(' + (currentPage - 1) + ')"' + (disableFirst ? ' disabled' : '') + '>' + escapeHtml(prevPageLabel) + '</button>';
    html += '<span class="pagination-page">' + escapeHtml(pageInfoText) + '</span>';
    html += '<button type="button" class="btn-secondary" onclick="' + escapeHtml(goPageName) + '(' + (currentPage + 1) + ')"' + (disableLast ? ' disabled' : '') + '>' + escapeHtml(nextPageLabel) + '</button>';
    html += '<button type="button" class="btn-secondary" onclick="' + escapeHtml(goPageName) + '(' + totalPages + ')"' + (disableLast ? ' disabled' : '') + '>' + escapeHtml(lastPageLabel) + '</button>';
    html += '</div></div>';
    container.innerHTML = html;
}

function showApprovalFeedback(id, message, isError) {
    const element = document.getElementById(id);
    if (!element) return;
    element.textContent = String(message || '');
    element.hidden = !message;
    element.className = 'hitl-apply-feedback' + (isError ? ' hitl-apply-feedback--error' : '');
}

// 待审计列表自动刷新兜底：服务端状态变化（重启取消、超时过期、他处决策）
// 需要反映到已打开的页面，否则会出现"僵尸待审"条目。
let hitlPendingAutoTimer = null;
function ensureHitlPendingAutoRefresh() {
    if (typeof setInterval !== 'function') return;
    if (hitlPendingAutoTimer) return;
    hitlPendingAutoTimer = setInterval(function () {
        if (document.hidden) return;
        if (hitlActiveTab !== 'pending') return;
        const panel = document.getElementById('hitl-panel-pending');
        if (!panel || panel.hidden) return;
        refreshHitlPending();
    }, 30000);
}

function setApprovalPolicySaveEnabled(enabled) {
    const button = document.getElementById('approval-policy-save');
    if (button) button.disabled = !enabled;
}

function applyApprovalPolicies(effective) {
    const source = effective && typeof effective === 'object' ? effective : {};
    const tool = Object.assign({ enabled: false, toolWhitelist: [] }, source.toolApproval || {});
    const danger = Object.assign({ enabled: true }, source.dangerousAction || {});
    const toolEnabled = document.getElementById('approval-tool-enabled');
    const dangerEnabled = document.getElementById('approval-danger-enabled');
    const reviewer = document.getElementById('approval-reviewer');
    const timeout = document.getElementById('approval-timeout-seconds');
    const whitelist = document.getElementById('approval-tool-whitelist');
    if (toolEnabled) toolEnabled.checked = tool.enabled === true;
    if (dangerEnabled) dangerEnabled.checked = danger.enabled !== false;
    if (reviewer) reviewer.value = source.reviewer === 'agent' ? 'agent' : 'human';
    if (timeout) timeout.value = Number(source.timeoutSeconds) || 300;
    if (whitelist) whitelist.value = (Array.isArray(tool.toolWhitelist) ? tool.toolWhitelist : []).join('\n');
    updateReviewerHint(reviewer && reviewer.value === 'agent' ? 'agent' : 'human');
}

function updateReviewerHint(mode) {
    const human = document.getElementById('approval-reviewer-hint-human');
    const agent = document.getElementById('approval-reviewer-hint-agent');
    if (human) human.hidden = mode !== 'human';
    if (agent) agent.hidden = mode !== 'agent';
}

// 危险硬闸卡片：显示当前启用规则数（与规则页签数据同源）。
function refreshDangerRuleCount() {
    const target = document.getElementById('approval-danger-rule-count');
    if (!target) return;
    hitlApiFetch('/api/approval-rules', { credentials: 'same-origin' })
        .then(function (response) { return response.ok ? response.json() : null; })
        .then(function (data) {
            const items = data && Array.isArray(data.items) ? data.items : [];
            const enabled = items.filter(function (item) { return item && item.enabled !== false; }).length;
            target.textContent = hitlT('ruleCountLine', '当前启用 {{count}} 条危险规则。', { count: enabled });
        })
        .catch(function () { /* 计数失败保持占位，不阻塞策略页 */ });
}

async function loadApprovalPolicies() {
    const sequence = ++approvalPolicyLoadSequence;
    setApprovalPolicySaveEnabled(false);
    showApprovalFeedback('approval-policy-feedback', '', false);
    try {
        const response = await hitlApiFetch('/api/approval-config', { credentials: 'same-origin' });
        if (!response.ok) throw new Error(await readHitlApiError(response));
        const data = await response.json();
        if (sequence !== approvalPolicyLoadSequence) return false;
        applyApprovalPolicies(data);
        refreshDangerRuleCount();
        setApprovalPolicySaveEnabled(true);
        return true;
    } catch (e) {
        if (sequence === approvalPolicyLoadSequence) {
            showApprovalFeedback('approval-policy-feedback', hitlT('policyLoadFailed', 'Failed to load policies: {{error}}', { error: e.message || String(e) }), true);
        }
        return false;
    }
}

async function saveApprovalPolicies() {
    const toolEnabled = document.getElementById('approval-tool-enabled');
    const dangerEnabled = document.getElementById('approval-danger-enabled');
    const reviewer = document.getElementById('approval-reviewer');
    const timeout = document.getElementById('approval-timeout-seconds');
    const whitelist = document.getElementById('approval-tool-whitelist');
    const payload = {
        reviewer: reviewer && reviewer.value === 'agent' ? 'agent' : 'human',
        timeoutSeconds: Math.max(1, Number(timeout && timeout.value) || 300),
        toolApproval: {
            enabled: toolEnabled ? toolEnabled.checked === true : false,
            toolWhitelist: String(whitelist ? whitelist.value : '').split(/\r?\n/).map(function (item) { return item.trim(); }).filter(Boolean)
        },
        dangerousAction: {
            enabled: dangerEnabled ? dangerEnabled.checked === true : false
        }
    };
    setApprovalPolicySaveEnabled(false);
    const saveButton = document.getElementById('approval-policy-save');
    const saveLabel = saveButton ? saveButton.textContent : '';
    if (saveButton) saveButton.textContent = hitlT('policySaving', '保存中…');
    showApprovalFeedback('approval-policy-feedback', '', false);
    try {
        const response = await hitlApiFetch('/api/approval-config', {
            method: 'PUT', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
        });
        if (!response.ok) throw new Error(await readHitlApiError(response));
        const reloaded = await loadApprovalPolicies();
        if (reloaded) {
            const savedMsg = hitlT('policySaved', 'Policies are active.');
            showApprovalFeedback('approval-policy-feedback', savedMsg, false);
            alert(savedMsg);
        }
    } catch (e) {
        const failMsg = hitlT('policySaveFailed', 'Failed to save policies: {{error}}', { error: e.message || String(e) });
        showApprovalFeedback('approval-policy-feedback', failMsg, true);
        alert(failMsg);
        setApprovalPolicySaveEnabled(true);
    } finally {
        if (saveButton) {
            saveButton.textContent = saveLabel || hitlT('policySave', '保存策略');
        }
    }
}

function renderApprovalRules(items) {
    const container = document.getElementById('approval-rules-list');
    if (!container) return;
    const list = Array.isArray(items) ? items : [];
    if (!list.length) {
        container.innerHTML = '<div class="empty-state">' + escapeHtml(hitlT('rulesEmpty', 'No approval rules')) + '</div>';
        return;
    }
    container.innerHTML = list.map(function (item, index) {
        const rule = item || {};
        const enabled = rule.enabled !== false;
        const matcherCount = Object.keys(rule.matcher || {}).length;
        const enabledLabel = enabled ? hitlT('ruleEnabled', 'Enabled') : hitlT('ruleDisabled', 'Disabled');
        return '<article class="approval-rule-card' + (enabled ? '' : ' is-disabled') + '" onclick="ruleCardClick(event, ' + index + ')">' +
            '<div class="approval-rule-card__top"><strong>' + escapeHtml(rule.id || '-') + '</strong></div>' +
            '<div class="approval-rule-card__meta"><span class="approval-rule-state approval-rule-state--' + (enabled ? 'enabled' : 'disabled') + '">' + escapeHtml(enabledLabel) + '</span>' +
            '<span>' + escapeHtml(approvalRiskLabel(rule.riskLevel)) + '</span>' +
            '<span>' + escapeHtml(hitlT('ruleMatcherCount', '{{count}} matcher groups', { count: matcherCount })) + '</span></div>' +
            '<div class="approval-rule-card__actions">' +
            '<button type="button" class="btn-link" onclick="viewApprovalRule(' + index + ')">' + escapeHtml(hitlT('ruleView', 'View')) + '</button>' +
            '<button type="button" class="btn-link" onclick="editApprovalRule(' + index + ')">' + escapeHtml(hitlT('ruleEdit', 'Edit')) + '</button>' +
            '<button type="button" class="btn-link" data-require-permission="approval:policy:write" onclick="disableApprovalRule(' + index + ')"' + (!enabled ? ' disabled' : '') + '>' + escapeHtml(hitlT('ruleDisable', 'Disable')) + '</button>' +
            '<button type="button" class="btn-link" data-require-permission="approval:policy:write" onclick="deleteApprovalRule(' + index + ')">' + escapeHtml(hitlT('ruleDelete', 'Delete')) + '</button></div></article>';
    }).join('');
}

// 只读详情：内置锁定规则不能编辑或停用，但完整匹配条件必须可查看。
function viewApprovalRule(index) {
    const view = ApprovalUIModel.toRuleView(approvalRulesCache[index]);
    const setText = function (id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    };
    setText('approval-rule-view-id', view.id);
    setText('approval-rule-view-priority', String(view.priority));
    setText('approval-rule-view-risk', approvalRiskLabel(view.riskLevel));
    setText('approval-rule-view-status', view.enabled ? hitlT('ruleEnabled', 'Enabled') : hitlT('ruleDisabled', 'Disabled'));
    const matcher = document.getElementById('approval-rule-view-matcher');
    if (matcher) matcher.textContent = view.matcherJson;
    const modal = document.getElementById('approval-rule-view-modal');
    if (modal) modal.style.display = 'flex';
}

function closeApprovalRuleViewModal() {
    const modal = document.getElementById('approval-rule-view-modal');
    if (modal) modal.style.display = 'none';
}

async function loadApprovalRules() {
    showApprovalFeedback('approval-rule-feedback', '', false);
    try {
        const response = await hitlApiFetch('/api/approval-rules', { credentials: 'same-origin' });
        if (!response.ok) throw new Error(await readHitlApiError(response));
        const data = await response.json();
        approvalRulesCache = Array.isArray(data.items) ? data.items : [];
        approvalRulesCache.sort(function (left, right) {
            return Number((right || {}).priority || 0) - Number((left || {}).priority || 0);
        });
        renderApprovalRules(approvalRulesCache);
    } catch (e) {
        const container = document.getElementById('approval-rules-list');
        if (container) container.innerHTML = '<div class="empty-state">' + escapeHtml(hitlT('ruleLoadFailed', 'Failed to load approval rules.')) + '</div>';
        showApprovalFeedback('approval-rule-feedback', hitlT('ruleLoadFailed', 'Failed to load approval rules: {{error}}', { error: e.message || String(e) }), true);
    }
}

function ruleCardClick(event, index) {
    // 卡片上的按钮（查看/编辑/停用/删除）自带行为，点击不重复触发选中。
    if (event && event.target && typeof event.target.closest === 'function' && event.target.closest('button')) return;
    editApprovalRule(index);
}

function resetApprovalRuleEditor() {
    const form = document.getElementById('approval-rule-editor');
    if (form) form.reset();
    const priority = document.getElementById('approval-rule-priority');
    const matcher = document.getElementById('approval-rule-matcher');
    if (priority) priority.value = '100';
    if (matcher) matcher.value = '{\n  "tools": ["exec"],\n  "textPatterns": ["(?i)rm\\\\s+-rf"]\n}';
    showApprovalFeedback('approval-rule-feedback', '', false);
}

function editApprovalRule(index) {
    const item = approvalRulesCache[index];
    const rule = item;
    if (!rule) return;
    const cards = document.querySelectorAll('#approval-rules-list .approval-rule-card');
    cards.forEach(function (card, cardIndex) {
        card.classList.toggle('is-selected', cardIndex === index);
    });
    document.getElementById('approval-rule-id').value = rule.id || '';
    document.getElementById('approval-rule-priority').value = String(rule.priority || 0);
    document.getElementById('approval-rule-risk').value = rule.riskLevel || 'high';
    document.getElementById('approval-rule-enabled').checked = rule.enabled !== false;
    document.getElementById('approval-rule-matcher').value = JSON.stringify(rule.matcher || {}, null, 2);
}

async function postApprovalRule(rule) {
    const response = await hitlApiFetch('/api/approval-rules', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rule)
    });
    if (!response.ok) throw new Error(await readHitlApiError(response));
    return response.json();
}

async function publishApprovalRule(event) {
    if (event && typeof event.preventDefault === 'function') event.preventDefault();
    let matcher;
    try {
        matcher = JSON.parse(document.getElementById('approval-rule-matcher').value || '{}');
        if (!matcher || typeof matcher !== 'object' || Array.isArray(matcher) || Object.keys(matcher).length === 0) {
            throw new Error(hitlT('ruleMatcherRequired', 'Matcher must not be empty.'));
        }
    } catch (e) {
        showApprovalFeedback('approval-rule-feedback', hitlT('ruleMatcherInvalid', 'Invalid matcher JSON: {{error}}', { error: e.message || String(e) }), true);
        return;
    }
    const button = document.getElementById('approval-rule-publish');
    if (button) button.disabled = true;
    const rule = {
            id: document.getElementById('approval-rule-id').value.trim(),
            enabled: document.getElementById('approval-rule-enabled').checked,
            priority: Number(document.getElementById('approval-rule-priority').value || 0),
            riskLevel: document.getElementById('approval-rule-risk').value,
            matcher: matcher
    };
    try {
        await postApprovalRule(rule);
        const publishedMsg = hitlT('rulePublished', 'Server validation passed and the rule was published.');
        showApprovalFeedback('approval-rule-feedback', publishedMsg, false);
        alert(publishedMsg);
        await loadApprovalRules();
    } catch (e) {
        const failMsg = hitlT('rulePublishFailed', 'Failed to publish rule: {{error}}', { error: e.message || String(e) });
        showApprovalFeedback('approval-rule-feedback', failMsg, true);
        alert(failMsg);
    } finally {
        if (button) button.disabled = false;
    }
}

async function disableApprovalRule(index) {
    const item = approvalRulesCache[index];
    const rule = item;
    if (!rule || !rule.enabled) return;
    if (!confirm(hitlT('ruleDisableConfirm', 'Disable rule {{id}}?', { id: rule.id }))) return;
    try {
        await postApprovalRule(Object.assign({}, rule, { enabled: false }));
        const disabledMsg = hitlT('ruleDisableSuccess', 'Rule disabled and now in effect.');
        showApprovalFeedback('approval-rule-feedback', disabledMsg, false);
        alert(disabledMsg);
        await loadApprovalRules();
    } catch (e) {
        const failMsg = hitlT('ruleDisableFailed', 'Failed to disable rule: {{error}}', { error: e.message || String(e) });
        showApprovalFeedback('approval-rule-feedback', failMsg, true);
        alert(failMsg);
    }
}

async function deleteApprovalRule(index) {
    const item = approvalRulesCache[index];
    const rule = item;
    if (!rule) return;
    if (!confirm(hitlT('ruleDeleteConfirm', 'Delete rule {{id}}?', { id: rule.id }))) return;
    try {
        const response = await hitlApiFetch('/api/approval-rules', {
            method: 'DELETE', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: rule.id })
        });
        if (!response.ok) throw new Error(await readHitlApiError(response));
        const deletedMsg = hitlT('ruleDeleteSuccess', 'Rule deleted.');
        showApprovalFeedback('approval-rule-feedback', deletedMsg, false);
        alert(deletedMsg);
        await loadApprovalRules();
    } catch (e) {
        const failMsg = hitlT('ruleDeleteFailed', 'Failed to delete rule: {{error}}', { error: e.message || String(e) });
        showApprovalFeedback('approval-rule-feedback', failMsg, true);
        alert(failMsg);
    }
}

function approvalRiskLabel(value) {
    const risk = String(value || '').trim().toLowerCase();
    const keys = { low: 'riskLow', medium: 'riskMedium', high: 'riskHigh', critical: 'riskCritical', prohibited: 'riskProhibited' };
    return keys[risk] ? hitlT(keys[risk], risk) : (risk || hitlT('notAvailable', 'Not available'));
}

function approvalStrategyLabel(value) {
    const strategy = String(value || '').trim().toLowerCase();
    const keys = { human: 'strategyHuman', agent: 'strategyAgent' };
    return keys[strategy] ? hitlT(keys[strategy], strategy) : (strategy || hitlT('notAvailable', 'Not available'));
}

function approvalSourceLabel(value) {
    const source = String(value || '').trim().toLowerCase();
    const keys = { workflow_node: 'sourceWorkflow', c2_task: 'sourceC2', tool: 'sourceTool' };
    return keys[source] ? hitlT(keys[source], source) : (source || hitlT('sourceTool', 'Tool'));
}

function approvalTriggerLabel(value) {
    const source = String(value || '').trim().toLowerCase();
    if (source === 'dangerous_action') return hitlT('dangerGateTitle', 'Dangerous-action hard gate');
    if (source === 'tool_approval') return hitlT('toolApprovalTitle', 'Tool approval');
    return approvalSourceLabel(source);
}

function renderHitlPendingList(items) {
    const list = Array.isArray(items) ? items : [];
    if (!list.length) return '';
    return list.map(function (item) {
        const payloadObject = item.arguments && typeof item.arguments === 'object' ? item.arguments : {};
        const payload = JSON.stringify(payloadObject, null, 2);
        const riskLevel = String(item.riskLevel || 'medium').trim().toLowerCase();
        const strategy = String(item.reviewer || 'human').trim().toLowerCase();
        const triggerSources = Array.isArray(item.triggerSources) ? item.triggerSources : [];
        const triggerHtml = triggerSources.map(function (source) {
            return '<span class="approval-trigger-tag approval-trigger-tag--' + escapeHtml(source) + '">' + escapeHtml(approvalTriggerLabel(source)) + '</span>';
        }).join('');
        const sourceLabel = approvalSourceLabel(item.source);
        const custodyRail = '<div class="approval-custody-rail" aria-label="' + escapeHtml(hitlT('custodyLabel', 'Approval chain')) + '">' +
            '<span class="is-done">' + escapeHtml(hitlT('custodyPolicy', 'Policy')) + '</span><i></i>' +
            '<span class="' + (strategy.indexOf('agent') >= 0 ? 'is-done' : 'is-skipped') + '">' + escapeHtml(hitlT('custodyAgent', 'Agent')) + '</span><i></i>' +
            '<span class="is-active">' + escapeHtml(hitlT('custodyHuman', 'Human')) + '</span><i></i>' +
            '<span>' + escapeHtml(hitlT('custodyExecute', 'Execute')) + '</span></div>';
        const rawId = String(item.id || '');
        const escapedId = escapeHtml(rawId);
        const quotedId = JSON.stringify(rawId).replace(/"/g, '&quot;');
        const quotedConversation = JSON.stringify(String(item.conversationId || '')).replace(/"/g, '&quot;');
        return '<div class="hitl-pending-item approval-card approval-card--' + escapeHtml(riskLevel) + '">' +
            '<div class="hitl-pending-item-header"><div class="hitl-pending-item-title">' +
            '<span class="hitl-tool-badge">' + escapeHtml(item.toolName || sourceLabel) + '</span>' +
            '<span class="approval-risk-tag approval-risk-tag--' + escapeHtml(riskLevel) + '">' + escapeHtml(approvalRiskLabel(riskLevel)) + '</span>' +
            '<span class="hitl-mode-tag">' + escapeHtml(approvalStrategyLabel(strategy)) + '</span></div></div>' +
            custodyRail +
            '<div class="approval-trigger-list">' + (triggerHtml || '<span class="approval-trigger-tag">' + escapeHtml(sourceLabel) + '</span>') + '</div>' +
            '<div class="hitl-pending-meta">' + escapeHtml(sourceLabel) + ' · ' + escapeHtml(hitlT('conversationLabel', 'Conversation:')) + ' ' + escapeHtml(item.conversationId || '-') + '</div>' +
            '<pre class="hitl-pending-payload">' + escapeHtml(payload) + '</pre>' +
            '<div class="hitl-input-help">' + escapeHtml(hitlT('commentHelp', 'Comment (optional): briefly note the approval reason.')) + '</div>' +
            '<input id="hitl-comment-' + escapedId + '" class="hitl-config-input hitl-inline-comment" type="text" placeholder="' + escapeHtml(hitlT('commentPlaceholder', 'e.g. allow read-only command')) + '">' +
            '<div class="hitl-pending-actions">' +
            '<button class="btn-secondary" data-require-permission="approval:decide" onclick="submitHitlDecision(' + quotedId + ',&quot;reject&quot;,' + quotedConversation + ')">' + escapeHtml(hitlT('reject', 'Reject')) + '</button>' +
            '<button class="btn-primary" data-require-permission="approval:decide" onclick="submitHitlDecision(' + quotedId + ',&quot;approve&quot;,' + quotedConversation + ')">' + escapeHtml(hitlT('approve', 'Approve')) + '</button>' +
            '</div></div>';
    }).join('');
}

async function refreshHitlPending() {
    const container = document.getElementById('hitl-pending-list');
    if (!container) return;
    hitlPendingLoaded = false;
    container.innerHTML = '<div class="loading-spinner">' + escapeHtml(hitlT('loading', 'Loading...')) + '</div>';
    let requestToken;
    try {
        const query = pendingQueryKey();
        requestToken = pendingRequestGate.begin(query);
        const response = await hitlApiFetch('/api/approvals?' + query, { credentials: 'same-origin' });
        if (!response.ok) throw new Error(await readHitlApiError(response));
        const data = await response.json();
        if (!pendingRequestGate.isCurrent(requestToken)) return;
        const items = Array.isArray(data.items) ? data.items : [];
        hitlPendingTotal = Number.isFinite(data.total) ? data.total : 0;
        const maxPage = Math.max(1, Math.ceil(hitlPendingTotal / hitlPendingPageSize));
        if (hitlPendingPage > maxPage) {
            hitlPendingPage = maxPage;
            await refreshHitlPending();
            return;
        }
        const badge = document.getElementById('hitl-pending-count');
        if (badge) {
            badge.textContent = String(hitlPendingTotal);
            badge.hidden = hitlPendingTotal <= 0;
        }
        hitlPendingCache = items;
        hitlPendingLoaded = true;
        const html = renderHitlPendingList(items);
        container.innerHTML = html || '<div class="empty-state">' + escapeHtml(hitlT('emptyState', 'No pending approvals')) + '</div>';
        if (typeof window.bindHitlAutoResizeTextareas === 'function') window.bindHitlAutoResizeTextareas(container);
        renderHitlPendingPagination();
    } catch (e) {
        if (!pendingRequestGate.isCurrent(requestToken)) return;
        hitlPendingLoaded = false;
        container.innerHTML = '<div class="empty-state">' + escapeHtml(hitlT('loadFailedWithError', 'Failed to load: {{error}}', { error: e.message || String(e) })) + '</div>';
        renderHitlPendingPagination();
    }
}

function filterHitlPending() {
    hitlPendingPage = 1;
    refreshHitlPending();
}

function pendingSearchValue() {
    const input = document.getElementById('hitl-pending-search');
    return input ? String(input.value || '').trim() : '';
}

function pendingQueryKey() {
    return ApprovalUIModel.buildApprovalQuery({
        status: 'pending_human',
        q: pendingSearchValue(),
        limit: hitlPendingPageSize,
        offset: (hitlPendingPage - 1) * hitlPendingPageSize
    });
}

async function submitHitlDecision(interruptId, decision, conversationIdOption) {
    const commentBox = document.getElementById('hitl-comment-' + interruptId);
    const comment = commentBox && commentBox.value ? commentBox.value.trim() : '';
    const currentConversation = typeof getCurrentConversationIdForHitl === 'function' ? getCurrentConversationIdForHitl() : '';
    return submitHitlDecisionWithPayload(interruptId, decision, comment, conversationIdOption || currentConversation);
}

async function submitHitlDecisionWithPayload(interruptId, decision, comment, conversationIdForFollow) {
    const approvalId = String(interruptId || '');
    const response = await hitlApiFetch('/api/approvals/' + encodeURIComponent(approvalId) + '/decision', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision: decision, comment: comment })
    });
    if (!response.ok) {
        // 409 即状态冲突（并发审批、状态已变更或旧端点已处理）：
        // 静默对账刷新，不依赖后端错误文案匹配。
        if (response.status === 409) {
            await refreshHitlPending();
            alert(hitlT('decisionConflict', 'This approval has already been processed; the pending list has been refreshed.'));
            return true;
        }
        const errorText = await readHitlApiError(response);
        alert(hitlT('submitFailedPrefix', 'Submit failed:') + ' ' + errorText);
        return false;
    }
    refreshHitlPending();
    const currentConversation = typeof getCurrentConversationIdForHitl === 'function' ? getCurrentConversationIdForHitl() : '';
    const conversationId = conversationIdForFollow || currentConversation;
    if (conversationId && typeof window.followAgentRunAfterHitlDecision === 'function') {
        window.followAgentRunAfterHitlDecision(conversationId);
    }
    return true;
}

function hitlParsePayloadObject(raw) {
    if (!raw) return {};
    if (typeof raw === 'object') return raw;
    try {
        const value = JSON.parse(String(raw));
        return value && typeof value === 'object' ? value : {};
    } catch (e) {
        return {};
    }
}

function hitlRenderContextBlocks(payloadObject) {
    if (!payloadObject || typeof payloadObject !== 'object') return '';
    const blocks = [];
    function addBlock(label, value) {
        const text = String(value || '').trim();
        if (!text) return;
        blocks.push('<div class="hitl-context-block"><div class="hitl-context-label">' + escapeHtml(label) + '</div>' +
            '<pre class="hitl-context-text">' + escapeHtml(text) + '</pre></div>');
    }
    addBlock(hitlT('fieldUserMessage', 'User message'), payloadObject.userMessage);
    addBlock(hitlT('fieldThinking', 'Thinking'), payloadObject.thinking);
    addBlock(hitlT('fieldReasoning', 'Reasoning'), payloadObject.reasoningChain);
    addBlock(hitlT('fieldPlanning', 'Planning'), payloadObject.planning);
    return blocks.join('');
}

// 审计日志摘要列：统一展示"这次调用做了什么"（命令 / 方法+URL / C2 动作），
// 有界截断；执行输出原文属于详情弹窗，不进列表以免撑高行。
function buildApprovalSummary(request) {
    const args = hitlParsePayloadObject(request && request.arguments);
    let action = '';
    if (args.command) action = String(args.command);
    else if (args.url) action = (args.method ? String(args.method).toUpperCase() + ' ' : '') + String(args.url);
    else if (args.script || args.code) action = String(args.script || args.code);
    else if (args.task_type) action = 'c2_task: ' + String(args.task_type);
    else {
        try { action = JSON.stringify(args); } catch (e) { action = ''; }
    }
    action = String(action).replace(/\s+/g, ' ').trim();
    if (action.length > 140) action = action.slice(0, 140) + '…';
    return action || hitlT('notAvailable', 'Not available');
}

function approvalDecisionLabel(decision) {
    const value = String(decision || '').trim().toLowerCase();
    const keys = { approve: 'decisionApprove', reject: 'decisionReject' };
    return keys[value] ? hitlT(keys[value], value) : (value || hitlT('noReviewDecision', 'No review decision'));
}

function approvalStatusLabel(status) {
    const value = String(status || '').trim().toLowerCase();
    const keys = {
        pending_agent: 'statusPendingAgent', pending_human: 'statusPendingHuman', approved: 'statusApproved',
        rejected: 'statusRejected', expired: 'statusExpired', cancelled: 'statusCancelled',
        executing: 'statusExecuting', succeeded: 'statusSucceeded', failed: 'statusFailed'
    };
    return keys[value] ? hitlT(keys[value], value) : (value || hitlT('notAvailable', 'Not available'));
}

function approvalStageLabel(stage) {
    const value = String(stage || '').trim().toLowerCase();
    const keys = {
        agent_review: 'stageAgentReview', human_review: 'stageHumanReview', approved: 'stageApproved',
        execution: 'stageExecution', terminal: 'stageTerminal'
    };
    return keys[value] ? hitlT(keys[value], value) : (value || hitlT('notAvailable', 'Not available'));
}

function approvalActorLabel(actorType) {
    const value = String(actorType || '').trim().toLowerCase();
    const keys = { human: 'reviewerHuman', agent: 'reviewerAgent', audit_agent: 'reviewerAgent', system: 'reviewerSystem' };
    return keys[value] ? hitlT(keys[value], value) : (value || hitlT('notAvailable', 'Not available'));
}

function approvalDecisionTag(decision) {
    const value = String(decision || '').trim().toLowerCase();
    const className = value === 'approve' ? ' hitl-decision--approve' : (value === 'reject' ? ' hitl-decision--reject' : '');
    return '<span class="hitl-decision-tag' + className + '">' + escapeHtml(approvalDecisionLabel(value)) + '</span>';
}

function renderHitlLogsTable(items) {
    const wrap = document.getElementById('hitl-logs-table-wrap');
    if (!wrap) return;
    const list = Array.isArray(items) ? items : [];
    if (!list.length) {
        wrap.innerHTML = '<div class="empty-state"><p>' + escapeHtml(hitlT('logsEmpty', 'No audit logs')) + '</p>' +
            '<p class="hitl-logs-empty-hint">' + escapeHtml(hitlT('logsEmptyHint', 'Approval records appear here after execution finishes.')) + '</p></div>';
        renderHitlLogsPagination();
        return;
    }
    const rows = list.map(function (request) {
        const view = ApprovalUIModel.toAuditView(request);
        const rawId = String(request.id || '');
        const quotedId = JSON.stringify(rawId).replace(/"/g, '&quot;');
        const lastDecision = view.decisions.length ? view.decisions[view.decisions.length - 1] : null;
        const summary = buildApprovalSummary(request);
        return '<tr><td class="hitl-logs-cell-mono">' + escapeHtml(rawId) + '</td>' +
            '<td>' + escapeHtml(String(request.toolName || '-')) + '</td>' +
            '<td class="hitl-logs-cell-mono">' + escapeHtml(String(request.conversationId || '-')) + '</td>' +
            '<td>' + approvalDecisionTag(view.reviewDecision) + '</td>' +
            '<td><span class="approval-execution-status approval-execution-status--' + escapeHtml(view.executionStatus) + '">' + escapeHtml(approvalStatusLabel(view.executionStatus)) + '</span></td>' +
            '<td>' + escapeHtml(lastDecision ? approvalActorLabel(lastDecision.actorType) : hitlT('notAvailable', 'Not available')) + '</td>' +
            '<td class="hitl-logs-summary" title="' + escapeHtml(summary).replace(/"/g, '&quot;') + '">' + escapeHtml(summary) + '</td>' +
            '<td>' + escapeHtml(approvalFormatTime(lastDecision ? lastDecision.createdAt : request.updatedAt || request.createdAt)) + '</td>' +
            '<td class="hitl-logs-actions"><button type="button" class="btn-link" onclick="openHitlLogModal(' + quotedId + ')">' + escapeHtml(hitlT('viewDetail', 'Detail')) + '</button></td></tr>';
    }).join('');
    wrap.innerHTML = '<table class="hitl-logs-table"><thead><tr>' +
        '<th>' + escapeHtml(hitlT('colId', 'ID')) + '</th>' +
        '<th>' + escapeHtml(hitlT('colTool', 'Tool')) + '</th>' +
        '<th>' + escapeHtml(hitlT('colConversation', 'Conversation')) + '</th>' +
        '<th>' + escapeHtml(hitlT('colReviewDecision', 'Review decision')) + '</th>' +
        '<th>' + escapeHtml(hitlT('colExecutionStatus', 'Execution status')) + '</th>' +
        '<th>' + escapeHtml(hitlT('colDecidedBy', 'Reviewer')) + '</th>' +
        '<th>' + escapeHtml(hitlT('colContext', 'Summary')) + '</th>' +
        '<th>' + escapeHtml(hitlT('colTime', 'Time')) + '</th>' +
        '<th>' + escapeHtml(hitlT('colActions', 'Actions')) + '</th>' +
        '</tr></thead><tbody>' + rows + '</tbody></table>';
    renderHitlLogsPagination();
}

async function refreshHitlLogs() {
    const wrap = document.getElementById('hitl-logs-table-wrap');
    if (!wrap) return;
    hitlLogsLoaded = false;
    wrap.innerHTML = '<div class="loading-spinner">' + escapeHtml(hitlT('loading', 'Loading...')) + '</div>';
    let requestToken;
    try {
        const query = auditQueryKey();
        requestToken = auditRequestGate.begin(query);
        const response = await hitlApiFetch('/api/approvals?' + query, { credentials: 'same-origin' });
        if (!response.ok) throw new Error(await readHitlApiError(response));
        const data = await response.json();
        if (!auditRequestGate.isCurrent(requestToken)) return;
        const items = Array.isArray(data.items) ? data.items : [];
        hitlLogsTotal = Number.isFinite(data.total) ? data.total : 0;
        const maxPage = Math.max(1, Math.ceil(hitlLogsTotal / hitlLogsPageSize));
        if (hitlLogsPage > maxPage) {
            hitlLogsPage = maxPage;
            await refreshHitlLogs();
            return;
        }
        hitlLogsCache = items;
        hitlLogsLoaded = true;
        renderHitlLogsTable(items);
    } catch (e) {
        if (!auditRequestGate.isCurrent(requestToken)) return;
        hitlLogsLoaded = false;
        wrap.innerHTML = '<div class="empty-state">' + escapeHtml(hitlT('loadFailedWithError', 'Failed to load: {{error}}', { error: e.message || String(e) })) + '</div>';
        renderHitlLogsPagination();
    }
}

function filterHitlLogs() {
    hitlLogsPage = 1;
    refreshHitlLogs();
}

function auditSearchValue() {
    const input = document.getElementById('hitl-logs-search');
    return input ? String(input.value || '').trim() : '';
}

function auditDecisionValue() {
    const select = document.getElementById('hitl-logs-decision-filter');
    const value = select ? String(select.value || '') : '';
    return value === 'all' ? '' : value;
}

function auditActorTypeValue() {
    const select = document.getElementById('hitl-logs-decidedby-filter');
    let value = select ? String(select.value || '') : '';
    if (value === 'audit_agent') value = 'agent';
    return value === 'all' ? '' : value;
}

function auditQueryKey() {
    return ApprovalUIModel.buildApprovalQuery({
        terminal: true,
        q: auditSearchValue(),
        decision: auditDecisionValue(),
        actorType: auditActorTypeValue(),
        limit: hitlLogsPageSize,
        offset: (hitlLogsPage - 1) * hitlLogsPageSize
    });
}

function hitlFormatPayloadForDisplay(raw) {
    if (!raw) return '';
    if (typeof raw === 'object') {
        try { return JSON.stringify(raw, null, 2); } catch (e) { return String(raw); }
    }
    const text = String(raw).trim();
    if (!text) return '';
    try { return JSON.stringify(JSON.parse(text), null, 2); } catch (e) { return text; }
}

function setApprovalDetailText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value || hitlT('notAvailable', 'Not available');
}

async function openHitlLogModal(idOption) {
    const modal = document.getElementById('hitl-log-modal');
    if (!modal || !idOption) return;
    try {
        const response = await hitlApiFetch('/api/approvals/' + encodeURIComponent(idOption), { credentials: 'same-origin' });
        if (!response.ok) throw new Error(await readHitlApiError(response));
        const request = await response.json();
        const view = ApprovalUIModel.toAuditView(request);
        const lastDecision = view.decisions.length ? view.decisions[view.decisions.length - 1] : null;
        setApprovalDetailText('hitl-log-detail-id', request.id);
        setApprovalDetailText('hitl-log-detail-tool', request.toolName);
        setApprovalDetailText('hitl-log-detail-conversation', request.conversationId);
        const decisionElement = document.getElementById('hitl-log-detail-decision');
        if (decisionElement) decisionElement.innerHTML = approvalDecisionTag(view.reviewDecision);
        setApprovalDetailText('hitl-log-detail-decided-by', lastDecision ? approvalActorLabel(lastDecision.actorType) + (lastDecision.actorId ? ' · ' + lastDecision.actorId : '') : hitlT('notAvailable', 'Not available'));
        setApprovalDetailText('hitl-log-detail-time', approvalFormatTime(lastDecision ? lastDecision.createdAt : request.updatedAt || request.createdAt));
        setApprovalDetailText('hitl-log-detail-risk', approvalRiskLabel(request.riskLevel));
        setApprovalDetailText('hitl-log-detail-triggers', (Array.isArray(request.triggerSources) ? request.triggerSources : []).map(approvalTriggerLabel).join(', '));
		setApprovalDetailText('hitl-log-detail-rules', view.matchedPolicies.join(', '));
        setApprovalDetailText('hitl-log-detail-execution-status', approvalStatusLabel(view.executionStatus));
        setApprovalDetailText('hitl-log-detail-execution-summary', view.executionSummary);
        const commentRow = document.getElementById('hitl-log-detail-comment-row');
        const commentElement = document.getElementById('hitl-log-detail-comment');
        const comment = lastDecision ? String(lastDecision.comment || '').trim() : '';
        if (commentRow && commentElement) {
            commentElement.textContent = comment;
            commentRow.hidden = !comment;
        }
        const decisionChain = document.getElementById('hitl-log-decision-chain');
        if (decisionChain) {
            decisionChain.innerHTML = view.decisions.length ? view.decisions.map(function (decision) {
                const actor = approvalActorLabel(decision.actorType) + (decision.actorId ? ' · ' + decision.actorId : '');
                return '<article class="approval-decision-chain__item"><div class="approval-decision-chain__head">' +
                    '<strong>' + escapeHtml(approvalStageLabel(decision.stage)) + '</strong>' + approvalDecisionTag(decision.decision) + '</div>' +
                    '<div class="approval-decision-chain__meta">' + escapeHtml(hitlT('decisionActor', 'Actor')) + ': ' + escapeHtml(actor) +
                    ' · ' + escapeHtml(approvalFormatTime(decision.createdAt)) + '</div>' +
                    (decision.comment ? '<p>' + escapeHtml(decision.comment) + '</p>' : '') + '</article>';
            }).join('') : '<div class="empty-state approval-decision-chain__empty">' + escapeHtml(hitlT('noReviewDecision', 'No review decision')) + '</div>';
        }
        const contextElement = document.getElementById('hitl-log-context-readonly');
        const contextHtml = hitlRenderContextBlocks(request.arguments || {});
        if (contextElement) {
            contextElement.innerHTML = contextHtml;
            contextElement.hidden = !contextHtml;
        }
        const executionElement = document.getElementById('hitl-log-execution-readonly');
        if (executionElement) {
            const executionHtml = view.executionSummary
                ? '<div class="hitl-context-block hitl-context-block--execution"><div class="hitl-context-label">' + escapeHtml(hitlT('executionSummary', 'Execution summary')) + '</div><pre class="hitl-context-text">' + escapeHtml(view.executionSummary) + '</pre></div>'
                : '';
            executionElement.innerHTML = executionHtml;
            executionElement.hidden = !executionHtml;
        }
        const payloadWrap = document.getElementById('hitl-log-detail-payload-wrap');
        const payloadElement = document.getElementById('hitl-log-detail-payload');
        const payloadText = hitlFormatPayloadForDisplay(request.arguments || {});
        if (payloadWrap && payloadElement) {
            payloadElement.textContent = payloadText;
            payloadWrap.hidden = !payloadText;
        }
        modal.style.display = 'flex';
    } catch (e) {
        alert(hitlT('loadFailedWithError', 'Failed to load: {{error}}', { error: e.message || String(e) }));
    }
}

function closeHitlLogModal() {
    const modal = document.getElementById('hitl-log-modal');
    if (modal) modal.style.display = 'none';
}

function renderHitlLogsPagination() {
    renderApprovalPagination('hitl-logs-pagination', {
        total: hitlLogsTotal, page: hitlLogsPage, pageSize: hitlLogsPageSize
    }, 'hitlLogsGoPage', 'onHitlLogsPageSizeChange', 'hitl-logs-page-size');
}

function renderHitlPendingPagination() {
    renderApprovalPagination('hitl-pending-pagination', {
        total: hitlPendingTotal, page: hitlPendingPage, pageSize: hitlPendingPageSize
    }, 'hitlPendingGoPage', 'onHitlPendingPageSizeChange', 'hitl-pending-page-size');
}

function onHitlLogsPageSizeChange() {
    const select = document.getElementById('hitl-logs-page-size');
    if (!select) return;
    const size = parseInt(select.value, 10);
    if (APPROVAL_PAGE_SIZE_OPTIONS.indexOf(size) < 0) return;
    hitlLogsPageSize = size;
    try { localStorage.setItem(APPROVAL_LOGS_PAGE_SIZE_KEY, String(size)); } catch (e) { /* ignore */ }
    hitlLogsPage = 1;
    refreshHitlLogs();
}

function onHitlPendingPageSizeChange() {
    const select = document.getElementById('hitl-pending-page-size');
    if (!select) return;
    const size = parseInt(select.value, 10);
    if (APPROVAL_PAGE_SIZE_OPTIONS.indexOf(size) < 0) return;
    hitlPendingPageSize = size;
    try { localStorage.setItem(APPROVAL_PENDING_PAGE_SIZE_KEY, String(size)); } catch (e) { /* ignore */ }
    hitlPendingPage = 1;
    refreshHitlPending();
}

function hitlLogsGoPage(page) {
    const totalPages = Math.max(1, Math.ceil((hitlLogsTotal || 0) / (hitlLogsPageSize || 20)));
    if (page < 1 || page > totalPages) return;
    hitlLogsPage = page;
    refreshHitlLogs();
}

function hitlPendingGoPage(page) {
    const totalPages = Math.max(1, Math.ceil((hitlPendingTotal || 0) / (hitlPendingPageSize || 20)));
    if (page < 1 || page > totalPages) return;
    hitlPendingPage = page;
    refreshHitlPending();
}

const APPROVAL_LOG_FILTER_SELECT_IDS = ['hitl-logs-decision-filter', 'hitl-logs-decidedby-filter'];
const approvalLogFilterSelectMap = {};
let approvalLogFilterSelectDocumentBound = false;
const APPROVAL_FILTER_SELECT_CARET = '<svg class="hitl-filter-select-caret" width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

function closeAllApprovalLogFilterSelects() {
    Object.keys(approvalLogFilterSelectMap).forEach(function (id) {
        const registered = approvalLogFilterSelectMap[id];
        if (!registered || !registered.wrapper) return;
        registered.wrapper.classList.remove('open');
        if (registered.trigger) registered.trigger.setAttribute('aria-expanded', 'false');
    });
}

function syncApprovalLogFilterSelect(selectId) {
    const registered = approvalLogFilterSelectMap[selectId];
    if (!registered) return;
    const select = registered.select;
    const dropdown = registered.dropdown;
    const trigger = registered.trigger;
    const valueSpan = trigger.querySelector('.hitl-filter-select-value');
    dropdown.innerHTML = '';
    Array.prototype.forEach.call(select.options, function (option) {
        const item = document.createElement('button');
        item.type = 'button';
        item.className = 'hitl-filter-select-option';
        item.setAttribute('role', 'option');
        item.setAttribute('data-value', option.value);
        item.setAttribute('aria-selected', option.value === select.value ? 'true' : 'false');
        if (option.value === select.value) item.classList.add('is-selected');
        const check = document.createElement('span');
        check.className = 'hitl-filter-select-check';
        check.setAttribute('aria-hidden', 'true');
        check.textContent = '✓';
        const label = document.createElement('span');
        label.className = 'hitl-filter-select-label';
        label.textContent = option.textContent;
        item.appendChild(check);
        item.appendChild(label);
        dropdown.appendChild(item);
    });
    const selected = select.options[select.selectedIndex];
    if (valueSpan) valueSpan.textContent = selected ? selected.textContent : '';
    trigger.disabled = !!select.disabled;
    registered.wrapper.classList.toggle('is-disabled', !!select.disabled);
}

function syncAllApprovalLogFilterSelects() {
    APPROVAL_LOG_FILTER_SELECT_IDS.forEach(syncApprovalLogFilterSelect);
}

function enhanceApprovalLogFilterSelect(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return;
    if (select.dataset.hitlCustomSelect === '1') {
        syncApprovalLogFilterSelect(selectId);
        return;
    }
    select.dataset.hitlCustomSelect = '1';
    select.classList.add('hitl-filter-native-select');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');
    const wrapper = document.createElement('div');
    wrapper.className = 'hitl-filter-select-ui';
    wrapper.classList.add(selectId === 'hitl-logs-decision-filter' ? 'hitl-filter-select-ui--decision' : 'hitl-filter-select-ui--decidedby');
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'hitl-filter-select-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    const valueSpan = document.createElement('span');
    valueSpan.className = 'hitl-filter-select-value';
    trigger.appendChild(valueSpan);
    trigger.insertAdjacentHTML('beforeend', APPROVAL_FILTER_SELECT_CARET);
    const dropdown = document.createElement('div');
    dropdown.className = 'hitl-filter-select-dropdown';
    dropdown.setAttribute('role', 'listbox');
    const parent = select.parentNode;
    parent.insertBefore(wrapper, select);
    wrapper.appendChild(trigger);
    wrapper.appendChild(dropdown);
    wrapper.appendChild(select);
    approvalLogFilterSelectMap[selectId] = { wrapper: wrapper, trigger: trigger, dropdown: dropdown, select: select };
    trigger.addEventListener('click', function (event) {
        event.stopPropagation();
        if (select.disabled) return;
        const open = wrapper.classList.contains('open');
        closeAllApprovalLogFilterSelects();
        if (!open) {
            wrapper.classList.add('open');
            trigger.setAttribute('aria-expanded', 'true');
        }
    });
    dropdown.addEventListener('click', function (event) {
        const option = event.target.closest('.hitl-filter-select-option');
        if (!option) return;
        event.stopPropagation();
        const value = option.getAttribute('data-value');
        if (value !== null && select.value !== value) {
            select.value = value;
            select.dispatchEvent(new Event('change', { bubbles: true }));
        }
        wrapper.classList.remove('open');
        trigger.setAttribute('aria-expanded', 'false');
        syncApprovalLogFilterSelect(selectId);
    });
    select.addEventListener('change', function () { syncApprovalLogFilterSelect(selectId); });
}

function initApprovalLogFilterSelects() {
    if (!approvalLogFilterSelectDocumentBound) {
        document.addEventListener('click', closeAllApprovalLogFilterSelects);
        document.addEventListener('keydown', function (event) {
            if (event.key === 'Escape') closeAllApprovalLogFilterSelects();
        });
        approvalLogFilterSelectDocumentBound = true;
    }
    APPROVAL_LOG_FILTER_SELECT_IDS.forEach(function (id) {
        enhanceApprovalLogFilterSelect(id);
        const select = document.getElementById(id);
        if (select && !select.dataset.hitlFilterBound) {
            select.dataset.hitlFilterBound = '1';
            select.addEventListener('change', filterHitlLogs);
        }
    });
    syncAllApprovalLogFilterSelects();
}

function switchHitlPageTab(tab) {
    const tabs = ['pending', 'policy', 'rules', 'logs'];
    hitlActiveTab = tabs.indexOf(tab) >= 0 ? tab : 'pending';
    tabs.forEach(function (name) {
        const tabElement = document.getElementById('hitl-tab-' + name);
        const panelElement = document.getElementById('hitl-panel-' + name);
        if (tabElement) {
            const active = hitlActiveTab === name;
            tabElement.classList.toggle('hitl-page-tab--active', active);
            tabElement.setAttribute('aria-selected', active ? 'true' : 'false');
        }
        if (panelElement) panelElement.hidden = hitlActiveTab !== name;
    });
    refreshHitlActivePanel();
}

function refreshHitlActivePanel() {
    if (hitlActiveTab === 'logs') refreshHitlLogs();
    else if (hitlActiveTab === 'policy') loadApprovalPolicies();
    else if (hitlActiveTab === 'rules') loadApprovalRules();
    else refreshHitlPending();
}

function refreshApprovalUII18n() {
    if (document.getElementById('hitl-logs-table-wrap') && hitlLogsLoaded) renderHitlLogsTable(hitlLogsCache);
    const pendingContainer = document.getElementById('hitl-pending-list');
    if (pendingContainer && hitlPendingLoaded) {
        pendingContainer.innerHTML = renderHitlPendingList(hitlPendingCache) ||
            '<div class="empty-state">' + escapeHtml(hitlT('emptyState', 'No pending approvals')) + '</div>';
    }
    if (document.getElementById('approval-rules-list') && approvalRulesCache.length) renderApprovalRules(approvalRulesCache);
    syncAllApprovalLogFilterSelects();
    renderHitlLogsPagination();
    renderHitlPendingPagination();
}

window.refreshHitlPending = refreshHitlPending;
window.fetchAllPendingApprovals = fetchAllPendingApprovals;
window.refreshHitlLogs = refreshHitlLogs;
window.refreshHitlActivePanel = refreshHitlActivePanel;
window.switchHitlPageTab = switchHitlPageTab;
window.hitlLogsGoPage = hitlLogsGoPage;
window.hitlPendingGoPage = hitlPendingGoPage;
window.filterHitlLogs = filterHitlLogs;
window.filterHitlPending = filterHitlPending;
window.onHitlLogsPageSizeChange = onHitlLogsPageSizeChange;
window.onHitlPendingPageSizeChange = onHitlPendingPageSizeChange;
window.submitHitlDecision = submitHitlDecision;
window.submitHitlDecisionWithPayload = submitHitlDecisionWithPayload;
window.loadApprovalPolicies = loadApprovalPolicies;
window.saveApprovalPolicies = saveApprovalPolicies;
window.loadApprovalRules = loadApprovalRules;
window.publishApprovalRule = publishApprovalRule;
window.editApprovalRule = editApprovalRule;
window.ruleCardClick = ruleCardClick;
window.disableApprovalRule = disableApprovalRule;
window.deleteApprovalRule = deleteApprovalRule;
window.viewApprovalRule = viewApprovalRule;
window.closeApprovalRuleViewModal = closeApprovalRuleViewModal;
window.resetApprovalRuleEditor = resetApprovalRuleEditor;
window.openHitlLogModal = openHitlLogModal;
window.closeHitlLogModal = closeHitlLogModal;

window.addEventListener('hitl-interrupt', function () {
    if (typeof window.currentPage === 'function' && window.currentPage() === 'hitl') refreshHitlActivePanel();
});

document.addEventListener('DOMContentLoaded', function () {
    initApprovalPageSize(APPROVAL_LOGS_PAGE_SIZE_KEY, 20, function (size) { hitlLogsPageSize = size; });
    initApprovalPageSize(APPROVAL_PENDING_PAGE_SIZE_KEY, 20, function (size) { hitlPendingPageSize = size; });
    initApprovalLogFilterSelects();
    setApprovalPolicySaveEnabled(false);
    const reviewerSelect = document.getElementById('approval-reviewer');
    if (reviewerSelect && !reviewerSelect.dataset.hintBound) {
        reviewerSelect.dataset.hintBound = '1';
        reviewerSelect.addEventListener('change', function () {
            updateReviewerHint(reviewerSelect.value === 'agent' ? 'agent' : 'human');
        });
    }
    ensureHitlPendingAutoRefresh();
});

document.addEventListener('languagechange', function () {
    try { refreshApprovalUII18n(); } catch (e) { console.warn('languagechange approval UI refresh failed', e); }
});
