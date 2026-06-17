function hitlModeNormalize(m) {
    let v = String(m || '').trim().toLowerCase().replace(/-/g, '_');
    if (v === 'feedback' || v === 'followup') {
        v = 'approval';
    }
    const allowed = ['off', 'approval', 'review_edit'];
    return allowed.indexOf(v) >= 0 ? v : 'off';
}

function hitlT(key, fallback, params) {
    const fullKey = 'hitl.' + key;
    try {
        if (typeof window.t === 'function') {
            const translated = window.t(fullKey, params || {});
            if (typeof translated === 'string' && translated && translated !== fullKey) {
                return translated;
            }
        }
    } catch (e) {}
    return fallback;
}

function hitlEffectiveEnabled(cfg) {
    if (!cfg) return false;
    if (cfg.enabled === true) return true;
    return hitlModeNormalize(cfg.mode) !== 'off';
}

function readHitlLocalStorageConv(conversationId) {
    if (!conversationId) return null;
    try {
        const key = 'cyberstrike-chat-hitl:' + String(conversationId).trim();
        const raw = localStorage.getItem(key);
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object') return null;
        return parsed;
    } catch (e) {
        return null;
    }
}

function hitlSensitiveToolsToArray(config) {
    if (Array.isArray(config && config.sensitiveTools)) return config.sensitiveTools;
    const s = config && config.sensitiveTools;
    if (typeof s === 'string') {
        return s.split(/[,\n\r]+/).map(function (x) { return x.trim(); }).filter(Boolean);
    }
    return [];
}

function normalizeHitlTimeoutSeconds(v, fallback) {
    const n = Number(v);
    if (Number.isFinite(n)) {
        return n > 0 ? Math.floor(n) : 0;
    }
    const f = Number(fallback);
    if (Number.isFinite(f)) {
        return f > 0 ? Math.floor(f) : 0;
    }
    return 0;
}

function getCurrentConversationIdForHitl() {
    if (typeof window.currentConversationId === 'string' && window.currentConversationId) {
        return window.currentConversationId;
    }
    const active = document.querySelector('.conversation-item.active');
    if (active && active.dataset && active.dataset.conversationId) {
        return active.dataset.conversationId;
    }
    return '';
}

async function fetchHitlConversationConfig(conversationId) {
    if (!conversationId) return null;
    const resp = await hitlApiFetch('/api/hitl/config/' + encodeURIComponent(conversationId), { credentials: 'same-origin' });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (!data || !data.hitl) return null;
    return {
        hitl: data.hitl,
        hitlGlobalToolWhitelist: Array.isArray(data.hitlGlobalToolWhitelist) ? data.hitlGlobalToolWhitelist : []
    };
}

/** 无会话时：将免审批工具合并进服务端 config.yaml，返回更新后的全局白名单数组 */
async function mergeHitlGlobalToolWhitelist(sensitiveTools) {
    const list = Array.isArray(sensitiveTools) ? sensitiveTools : [];
    const resp = await hitlApiFetch('/api/hitl/tool-whitelist', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sensitiveTools: list })
    });
    if (!resp.ok) {
        const msg = await readHitlApiError(resp);
        throw new Error(msg || ('HTTP ' + resp.status));
    }
    const data = await resp.json();
    if (data && Array.isArray(data.hitlGlobalToolWhitelist)) {
        return data.hitlGlobalToolWhitelist;
    }
    return [];
}

async function saveHitlConversationConfig(conversationId, config) {
    if (!conversationId || !config) return false;
    const mode = hitlModeNormalize(config.mode || 'off');
    const enabled = typeof config.enabled === 'boolean' ? config.enabled : (mode !== 'off');
    const sensitiveTools = hitlSensitiveToolsToArray(config);
    const timeoutSeconds = normalizeHitlTimeoutSeconds(config.timeoutSeconds, 0);
    const resp = await hitlApiFetch('/api/hitl/config', {
        method: 'PUT',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            conversationId: conversationId,
            enabled: enabled,
            mode: mode,
            sensitiveTools: sensitiveTools,
            timeoutSeconds: timeoutSeconds
        })
    });
    if (!resp.ok) {
        const msg = await readHitlApiError(resp);
        throw new Error(msg || ('HTTP ' + resp.status));
    }
    return true;
}

async function syncHitlConfigFromServer(conversationId) {
    const pack = await fetchHitlConversationConfig(conversationId);
    if (!pack || !pack.hitl) return;
    const cfg = pack.hitl;
    const globalWL = pack.hitlGlobalToolWhitelist || [];
    if (typeof window !== 'undefined') {
        window.csaiHitlGlobalToolWhitelist = globalWL;
    }
    const strip = typeof window.hitlStripGlobalToolsFromFormString === 'function'
        ? window.hitlStripGlobalToolsFromFormString
        : function (_g, s) { return typeof s === 'string' ? s.trim() : ''; };

    let merged = cfg;
    if (!hitlEffectiveEnabled(cfg)) {
        const local = readHitlLocalStorageConv(conversationId);
        const localMode = local && local.mode ? hitlModeNormalize(local.mode) : 'off';
        if (localMode !== 'off') {
            let localToolsStr = typeof local.sensitiveTools === 'string' ? local.sensitiveTools : '';
            localToolsStr = strip(globalWL, localToolsStr);
            merged = {
                enabled: true,
                mode: localMode,
                sensitiveTools: localToolsStr.split(/[,\n\r]+/).map(function (s) { return s.trim(); }).filter(Boolean),
                timeoutSeconds: normalizeHitlTimeoutSeconds(cfg.timeoutSeconds, 0)
            };
            saveHitlConversationConfig(conversationId, {
                mode: localMode,
                sensitiveTools: localToolsStr,
                enabled: true,
                timeoutSeconds: merged.timeoutSeconds
            }).catch(function (err) {
                console.warn('HITL 会话配置同步到服务器失败（将仅保留本地 UI）:', err);
            });
        } else {
            const gl = typeof window.getHitlLastGlobalConfig === 'function' ? window.getHitlLastGlobalConfig() : null;
            const glMode = gl && gl.mode ? hitlModeNormalize(gl.mode) : 'off';
            if (glMode !== 'off') {
                let glToolsStr = typeof gl.sensitiveTools === 'string' ? gl.sensitiveTools : '';
                glToolsStr = strip(globalWL, glToolsStr);
                merged = {
                    enabled: true,
                    mode: glMode,
                    sensitiveTools: glToolsStr.split(/[,\n\r]+/).map(function (s) { return s.trim(); }).filter(Boolean),
                    timeoutSeconds: normalizeHitlTimeoutSeconds(cfg.timeoutSeconds, 0)
                };
                saveHitlConversationConfig(conversationId, {
                    mode: glMode,
                    sensitiveTools: glToolsStr,
                    enabled: true,
                    timeoutSeconds: merged.timeoutSeconds
                }).catch(function (err) {
                    console.warn('HITL 会话配置同步到服务器失败（将仅保留本地 UI）:', err);
                });
            }
        }
    }
    const uiMode = hitlEffectiveEnabled(merged) ? hitlModeNormalize(merged.mode) : 'off';
    const rawArr = Array.isArray(merged.sensitiveTools)
        ? merged.sensitiveTools
        : hitlSensitiveToolsToArray({ sensitiveTools: merged.sensitiveTools });
    const sessionOnlyStr = strip(globalWL, rawArr.join(', '));
    const normalizedCfg = Object.assign({}, merged, {
        mode: uiMode,
        sensitiveTools: sessionOnlyStr
    });
    if (typeof window.saveHitlConfigForConversation === 'function') {
        window.saveHitlConfigForConversation(conversationId, normalizedCfg);
    } else {
        try {
            localStorage.setItem('chat_hitl_config_' + conversationId, JSON.stringify(normalizedCfg));
        } catch (e) {}
    }
    if (typeof window.applyHitlConfigToUI === 'function') {
        window.applyHitlConfigToUI(normalizedCfg);
    }
    reconcileHitlUiState();
}

async function syncHitlConfigToServerByCurrentConversation() {
    const conversationId = getCurrentConversationIdForHitl();
    if (!conversationId) return;
    if (typeof window.readHitlConfigFromForm !== 'function') return;
    const cfg = window.readHitlConfigFromForm();
    await saveHitlConversationConfig(conversationId, cfg);
}

function reconcileHitlUiState() {
    if (typeof window.readHitlConfigFromForm === 'function' && typeof window.updateHitlStatusUI === 'function') {
        try {
            const cfg = window.readHitlConfigFromForm();
            window.updateHitlStatusUI(cfg);
        } catch (e) {}
    }
}

let hitlFollowRunSeq = 0;

/**
 * 审批提交后原 SSE 已断开：轮询任务列表，运行中则拉取过程详情；任务结束后再整页加载会话以对齐终态。
 */
async function followAgentRunAfterHitlDecision(conversationId) {
    if (!conversationId || typeof apiFetch !== 'function') return;
    if (typeof window.attachRunningTaskEventStream === 'function') {
        try {
            const attached = await window.attachRunningTaskEventStream(conversationId);
            if (attached) return;
        } catch (e) {
            console.warn('attachRunningTaskEventStream', e);
        }
    }
    var mySeq = ++hitlFollowRunSeq;
    var intervalMs = 2000;
    var firstDelayMs = 500;
    var maxMs = 30 * 60 * 1000;
    var deadline = Date.now() + maxMs;

    function taskStillActive(cid) {
        return apiFetch('/api/agent-loop/tasks').then(function (r) {
            if (!r.ok) return false;
            return r.json().then(function (j) {
                var tasks = (j && j.tasks) ? j.tasks : [];
                return tasks.some(function (t) {
                    return t && t.conversationId === cid && (t.status === 'running' || t.status === 'cancelling');
                });
            });
        }).catch(function () { return false; });
    }

    await new Promise(function (r) { setTimeout(r, firstDelayMs); });

    while (mySeq === hitlFollowRunSeq) {
        if (Date.now() > deadline) {
            if (typeof window.loadConversation === 'function' && window.currentConversationId === conversationId) {
                await window.loadConversation(conversationId);
            }
            if (typeof loadActiveTasks === 'function') loadActiveTasks();
            return;
        }
        try {
            var active = await taskStillActive(conversationId);
            var onThisConv = (typeof window.currentConversationId === 'string' && window.currentConversationId === conversationId);
            if (onThisConv && typeof window.refreshLastAssistantProcessDetails === 'function') {
                await window.refreshLastAssistantProcessDetails(conversationId);
            }
            if (!active) {
                await new Promise(function (r) { setTimeout(r, 450); });
                if (typeof window.loadConversation === 'function' && window.currentConversationId === conversationId) {
                    await window.loadConversation(conversationId);
                }
                if (typeof loadActiveTasks === 'function') loadActiveTasks();
                return;
            }
        } catch (e) {
            console.warn('followAgentRunAfterHitlDecision', e);
        }
        await new Promise(function (r) { setTimeout(r, intervalMs); });
    }
}

async function refreshHitlPending() {
    const container = document.getElementById('hitl-pending-list');
    if (!container) return;
    container.innerHTML = '<div class="loading-spinner">' + escapeHtml(hitlT('loading', 'Loading...')) + '</div>';
    try {
        const resp = await hitlApiFetch('/api/hitl/pending', { credentials: 'same-origin' });
        if (!resp.ok) {
            throw new Error('request failed');
        }
        const data = await resp.json();
        const items = Array.isArray(data.items) ? data.items : [];
        if (!items.length) {
            container.innerHTML = '<div class="empty-state">' + escapeHtml(hitlT('emptyState', 'No pending approvals')) + '</div>';
            return;
        }
        container.innerHTML = items.map(function (item) {
            const payload = String(item.payload || '');
            const preview = payload.length > 280 ? (payload.slice(0, 280) + '...') : payload;
            const mode = String(item.mode || '').trim().toLowerCase();
            const allowEdit = mode === 'review_edit';
            var escId = escapeHtml(String(item.id || ''));
            var qId = JSON.stringify(String(item.id || '')).replace(/"/g, '&quot;');
            var qConv = JSON.stringify(String(item.conversationId || '')).replace(/"/g, '&quot;');
            return (
                '<div class="hitl-pending-item">' +
                '<div class="hitl-pending-item-header">' +
                '<div class="hitl-pending-item-title">' +
                '<span class="hitl-tool-badge">' + escapeHtml(item.toolName || '-') + '</span>' +
                '<span class="hitl-mode-tag hitl-mode-tag--' + escapeHtml(mode) + '">' + escapeHtml(item.mode || '-') + '</span>' +
                '</div>' +
                '<button class="hitl-dismiss-btn" title="' + escapeHtml(hitlT('dismiss', 'Dismiss')) + '" onclick="dismissHitlItem(' + qId + ')">&times;</button>' +
                '</div>' +
                '<div class="hitl-pending-meta">' + escapeHtml(hitlT('conversationLabel', 'Conversation:')) + ' ' + escapeHtml(item.conversationId || '-') + '</div>' +
                '<pre class="hitl-pending-payload">' + escapeHtml(preview) + '</pre>' +
                (allowEdit
                    ? ('<div class="hitl-input-help">' + escapeHtml(hitlT('reviewEditHelp', 'Review & edit mode: provide a JSON object to override tool arguments. Example: {"command":"ls -la"}')) + '</div>' +
                       '<textarea id="hitl-edit-' + escId + '" class="hitl-edit-args" placeholder=\'{"command":"ls -la"}\'></textarea>')
                    : '<div class="hitl-input-help">' + escapeHtml(hitlT('approvalHelp', 'Approval mode: only approve/reject, argument editing is disabled.')) + '</div>') +
                '<div class="hitl-input-help">' + escapeHtml(hitlT('commentHelp', 'Comment (optional): briefly note the approval reason.')) + '</div>' +
                '<input id="hitl-comment-' + escId + '" class="hitl-config-input hitl-inline-comment" type="text" placeholder="' + escapeHtml(hitlT('commentPlaceholder', 'e.g. allow read-only command')) + '">' +
                '<div class="hitl-pending-actions">' +
                '<button class="btn-secondary" onclick="submitHitlDecision(' + qId + ',&quot;reject&quot;,' + qConv + ')">' + escapeHtml(hitlT('reject', 'Reject')) + '</button>' +
                '<button class="btn-primary" onclick="submitHitlDecision(' + qId + ',&quot;approve&quot;,' + qConv + ')">' + escapeHtml(hitlT('approve', 'Approve')) + '</button>' +
                '</div>' +
                '</div>'
            );
        }).join('');
    } catch (e) {
        container.innerHTML = '<div class="empty-state">' + escapeHtml(hitlT('loadFailed', 'Failed to load')) + '</div>';
    }
}

async function submitHitlDecision(interruptId, decision, conversationIdOpt) {
    const commentBox = document.getElementById('hitl-comment-' + interruptId);
    const comment = (commentBox && commentBox.value) ? commentBox.value.trim() : '';
    let editedArguments = null;
    const editBox = document.getElementById('hitl-edit-' + interruptId);
    if (editBox && editBox.value && editBox.value.trim()) {
        try {
            editedArguments = JSON.parse(editBox.value.trim());
        } catch (e) {
            alert(hitlT('invalidJson', 'Invalid JSON arguments'));
            return;
        }
    }
    const convFollow = conversationIdOpt || getCurrentConversationIdForHitl();
    return submitHitlDecisionWithPayload(interruptId, decision, comment, editedArguments, convFollow);
}

async function submitHitlDecisionWithPayload(interruptId, decision, comment, editedArguments, conversationIdForFollow) {
    const resp = await hitlApiFetch('/api/hitl/decision', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interruptId: interruptId, decision: decision, comment: comment, editedArguments: editedArguments })
    });
    if (!resp.ok) {
        const errText = await readHitlApiError(resp);
        if (resp.status === 409 && (errText.indexOf('already resolved') >= 0 || errText.indexOf('not found') >= 0)) {
            await dismissHitlItem(interruptId, true);
            return true;
        }
        alert(hitlT('submitFailedPrefix', 'Submit failed:') + ' ' + errText);
        return false;
    }
    refreshHitlPending();
    const cid = conversationIdForFollow || getCurrentConversationIdForHitl();
    if (cid) {
        followAgentRunAfterHitlDecision(cid);
    }
    return true;
}

async function hitlApiFetch(url, options) {
    if (typeof apiFetch === 'function') {
        return apiFetch(url, options || {});
    }
    return fetch(url, options || {});
}

async function readHitlApiError(resp) {
    try {
        const data = await resp.json();
        if (data && typeof data.error === 'string' && data.error.trim()) return data.error.trim();
        return 'HTTP ' + resp.status;
    } catch (e) {
        return 'HTTP ' + resp.status;
    }
}

async function dismissHitlItem(interruptId, silent) {
    try {
        await hitlApiFetch('/api/hitl/dismiss', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interruptId: interruptId })
        });
    } catch (e) {
        if (!silent) { console.warn('dismissHitlItem', e); }
    }
    refreshHitlPending();
}

window.refreshHitlPending = refreshHitlPending;
window.submitHitlDecision = submitHitlDecision;
window.submitHitlDecisionWithPayload = submitHitlDecisionWithPayload;
window.dismissHitlItem = dismissHitlItem;
window.followAgentRunAfterHitlDecision = followAgentRunAfterHitlDecision;

window.addEventListener('hitl-interrupt', function () {
    if (typeof window.currentPage === 'function' && window.currentPage() === 'hitl') {
        refreshHitlPending();
    }
});

window.addEventListener('pageshow', function () {
    setTimeout(reconcileHitlUiState, 0);
});
document.addEventListener('DOMContentLoaded', function () {
    setTimeout(reconcileHitlUiState, 0);
});

// 由 applyHitlSidebarConfig 调用，将侧栏配置同步到后端
window.syncHitlConfigToServerByCurrentConversation = syncHitlConfigToServerByCurrentConversation;
window.saveHitlConversationConfig = saveHitlConversationConfig;
window.mergeHitlGlobalToolWhitelist = mergeHitlGlobalToolWhitelist;

// 由 chat.js 在 loadConversation 内 await 调用；挂到 window 供其它入口显式触发
window.syncHitlConfigFromServer = syncHitlConfigFromServer;
