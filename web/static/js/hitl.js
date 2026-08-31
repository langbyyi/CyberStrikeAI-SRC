function hitlT(key, fallback, params) {
    const fullKey = 'hitl.' + key;
    try {
        if (typeof window.t === 'function') {
            const translated = window.t(fullKey, params || {});
            if (typeof translated === 'string' && translated && translated !== fullKey) return translated;
        }
    } catch (e) {}
    return fallback;
}

let hitlFollowRunSeq = 0;

function hitlAutoResizeTextarea(textarea) {
    if (!textarea) return;
    textarea.style.height = 'auto';
    textarea.style.height = Math.max(textarea.scrollHeight, textarea.offsetHeight || 0) + 'px';
}

function bindHitlAutoResizeTextareas(root) {
    const scope = root || document;
    if (!scope || !scope.querySelectorAll) return;
    scope.querySelectorAll('.hitl-edit-args').forEach(function (textarea) {
        if (!textarea.__hitlAutoResizeBound) {
            textarea.__hitlAutoResizeBound = true;
            textarea.addEventListener('input', function () { hitlAutoResizeTextarea(textarea); });
        }
        hitlAutoResizeTextarea(textarea);
    });
}

async function followAgentRunAfterHitlDecision(conversationId) {
    if (!conversationId || typeof apiFetch !== 'function') return;
    if (typeof window.attachRunningTaskEventStream === 'function') {
        try {
            if (await window.attachRunningTaskEventStream(conversationId)) return;
        } catch (e) {
            console.warn('attachRunningTaskEventStream', e);
        }
    }
    const mySeq = ++hitlFollowRunSeq;
    const deadline = Date.now() + 30 * 60 * 1000;
    await new Promise(function (resolve) { setTimeout(resolve, 500); });
    while (mySeq === hitlFollowRunSeq) {
        const response = await apiFetch('/api/agent-loop/tasks').catch(function () { return null; });
        let active = false;
        if (response && response.ok) {
            const data = await response.json();
            active = (data.tasks || []).some(function (task) {
                return task && task.conversationId === conversationId && (task.status === 'running' || task.status === 'cancelling');
            });
        }
        if (!active || Date.now() > deadline) {
            if (typeof window.loadConversation === 'function' && window.currentConversationId === conversationId) {
                await window.loadConversation(conversationId);
            }
            if (typeof loadActiveTasks === 'function') loadActiveTasks();
            return;
        }
        if (window.currentConversationId === conversationId && typeof window.refreshLastAssistantProcessDetails === 'function') {
            await window.refreshLastAssistantProcessDetails(conversationId);
        }
        await new Promise(function (resolve) { setTimeout(resolve, 2000); });
    }
}

async function hitlApiFetch(url, options) {
    if (typeof apiFetch === 'function') return apiFetch(url, options || {});
    return fetch(url, options || {});
}

async function readHitlApiError(response) {
    try {
        const data = await response.json();
        if (data && typeof data.error === 'string' && data.error.trim()) return data.error.trim();
    } catch (e) {}
    return 'HTTP ' + response.status;
}

window.bindHitlAutoResizeTextareas = bindHitlAutoResizeTextareas;
window.followAgentRunAfterHitlDecision = followAgentRunAfterHitlDecision;
