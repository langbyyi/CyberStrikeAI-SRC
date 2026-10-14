/** Project defaults and immutable task specifications. Drafts stay in memory. */
(function () {
    'use strict';
    const MAX_BYTES = 65536;
    const chatDrafts = new Map();
    const batchOverrides = new Map();
    let batchMessages = '';
    let dialogSave = null;
    let openSequence = 0;
    let generation = 0;
    const el = id => document.getElementById(id);
    const tr = key => typeof window.t === 'function' ? window.t('testingSpec.' + key) : key;
    function node(tag, text, attrs = {}) {
        const result = document.createElement(tag);
        if (text) result.textContent = text;
        Object.entries(attrs).forEach(([key, value]) => result.setAttribute(key, value));
        return result;
    }
    function translated(tag, key, attrs = {}) { return node(tag, tr(key), { 'data-i18n': 'testingSpec.' + key, ...attrs }); }
    function validate(spec) {
        if (new TextEncoder().encode(spec.content).length > MAX_BYTES || spec.content.includes('\0')) throw new Error(tr('invalidContent'));
        if (Array.from(spec.name).length > 200 || /[\0\r\n]/.test(spec.name)) throw new Error(tr('invalidName'));
        return { name: spec.name.trim(), content: spec.content.replace(/\r\n/g, '\n').trim() };
    }
    async function parseFile(file) {
        if (!file || !/\.(md|markdown|txt)$/i.test(file.name) || file.size > MAX_BYTES) throw new Error(tr('invalidFile'));
        let content;
        try { content = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()); }
        catch (_) { throw new Error(tr('invalidContent')); }
        return validate({ name: file.name, content });
    }
    function fillEditor(prefix, spec) {
        if (el(prefix + '-name')) el(prefix + '-name').value = spec?.name || '';
        if (el(prefix + '-content')) el(prefix + '-content').value = spec?.content || '';
        const fileName = el(prefix + '-file-name');
        if (fileName) {
            fileName.textContent = spec?.name || tr('noFile');
            fileName.setAttribute('title', spec?.name || '');
            if (spec?.name) fileName.removeAttribute('data-i18n');
            else fileName.setAttribute('data-i18n', 'testingSpec.noFile');
        }
    }
    function readEditor(prefix) {
        if (!el(prefix + '-content')) return undefined;
        if (el(prefix + '-mode')?.value === 'inherit') return null;
        return validate({ name: el(prefix + '-name')?.value || '', content: el(prefix + '-content').value || '' });
    }
    function syncEditor(prefix, locked = false) {
        const inherit = el(prefix + '-mode')?.value === 'inherit';
        ['name', 'content', 'file', 'file-trigger'].forEach(suffix => { if (el(prefix + '-' + suffix)) el(prefix + '-' + suffix).disabled = inherit || locked; });
    }
    function editor(prefix, withMode) {
        const wrap = node('div', '', { class: 'testing-specification-fields' });
        if (withMode) {
            const mode = node('select', '', { id: prefix + '-mode', class: 'form-input', 'aria-label': tr('mode'), 'data-i18n': 'testingSpec.mode', 'data-i18n-attr': 'aria-label', 'data-i18n-skip-text': 'true' });
            mode.append(translated('option', 'inherit', { value: 'inherit' }), translated('option', 'override', { value: 'override' }));
            mode.addEventListener('change', () => syncEditor(prefix));
            wrap.append(mode);
        }
        wrap.append(translated('label', 'name', { for: prefix + '-name' }), node('input', '', { id: prefix + '-name', class: 'form-input', maxlength: '200', autocomplete: 'off' }));
        wrap.append(translated('label', 'import', { for: prefix + '-file' }));
        const file = node('input', '', { id: prefix + '-file', type: 'file', accept: '.md,.markdown,.txt', hidden: '' });
        const upload = node('div', '', { class: 'testing-specification-upload' });
        const trigger = node('button', '', { id: prefix + '-file-trigger', type: 'button', class: 'testing-specification-upload-trigger', 'aria-describedby': prefix + '-file-name' });
        const icon = node('span', '', { class: 'testing-specification-upload-icon', 'aria-hidden': 'true' });
        icon.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/></svg>';
        trigger.append(icon, translated('span', 'chooseFile'));
        trigger.addEventListener('click', () => { if (!file.disabled) file.click(); });
        upload.append(file, trigger, translated('span', 'noFile', { id: prefix + '-file-name', class: 'testing-specification-file-name', 'aria-live': 'polite' }));
        file.addEventListener('change', async () => {
            const currentGeneration = generation;
            const chosen = file.files?.[0];
            if (!chosen) return;
            try { const spec = await parseFile(chosen); if (generation === currentGeneration) fillEditor(prefix, spec); }
            catch (error) { window.alert(error.message); }
            finally { file.value = ''; }
        });
        wrap.append(upload, translated('label', 'content', { for: prefix + '-content' }), node('textarea', '', { id: prefix + '-content', rows: '9', class: 'form-input', spellcheck: 'false' }), translated('small', 'hint', { class: 'form-hint' }));
        return wrap;
    }
    function mountEditor(prefix, anchor, withMode, targetID) {
        const target = el(anchor)?.closest('.form-group, .projects-form-field');
        if (!target || el(prefix + '-content')) return;
        const details = node('details', '', { class: 'testing-specification-editor' });
        details.open = !withMode;
        const summary = node('summary', tr('title'), { 'data-i18n': 'testingSpec.title' });
        details.append(summary, editor(prefix, withMode));
        const destination = targetID && el(targetID);
        if (destination) destination.append(details);
        else target.after(details);
        syncEditor(prefix);
    }
    function scopeKey(conversationID, projectID) { return conversationID ? 'conversation:' + conversationID : 'project:' + (projectID || ''); }
    function setChatDraft(conversationID, projectID, spec) {
        const key = scopeKey(conversationID, projectID);
        if (spec == null) chatDrafts.delete(key); else chatDrafts.set(key, validate(spec));
    }
    function resetChat() { chatDrafts.clear(); }
    function applyToChat(body) {
        const key = scopeKey(body.conversationId, body.projectId);
        if (chatDrafts.has(key)) body.testingSpecification = { ...chatDrafts.get(key) };
    }
    function acceptChat(body) { chatDrafts.delete(scopeKey(body.conversationId, body.projectId)); }
    function acceptChatEvent(body, event) {
        if (!event || !['conversation', 'message_saved'].includes(event.type)) return;
        const conversationID = event.data?.conversationId;
        if (conversationID && (!body.conversationId || body.conversationId === conversationID)) acceptChat(body);
    }
    async function getJSON(url) {
        const response = await window.apiFetch(url);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || tr('loadFailed'));
        return data;
    }
    async function projectSpec(projectID) {
        if (!projectID) return null;
        const project = await getJSON('/api/projects/' + encodeURIComponent(projectID));
        return project.testing_specification || null;
    }
    function showDialog(spec, mode, locked, infoKey, save, hash) {
        const dialog = el('testing-specification-dialog');
        fillEditor('task-spec', spec);
        el('task-spec-mode').value = mode;
        el('task-spec-mode').disabled = locked;
        el('task-spec-mode').onchange = () => {
            if (el('task-spec-mode').value === 'inherit') fillEditor('task-spec', spec);
            syncEditor('task-spec', locked);
        };
        el('task-spec-save').hidden = locked;
        el('task-spec-save').disabled = locked;
        el('task-spec-info').setAttribute('data-i18n', 'testingSpec.' + infoKey);
        el('task-spec-info').textContent = tr(infoKey);
        el('task-spec-hash').textContent = hash ? 'SHA-256: ' + hash : '';
        el('task-spec-hash').hidden = !hash;
        syncEditor('task-spec', locked);
        dialogSave = save;
        el('task-spec-task').hidden = true;
        dialog.showModal();
    }
    async function openChat(conversationID, projectID) {
        const seq = ++openSequence;
        try {
            let snapshot = null;
            let locked = false;
            if (conversationID) {
                const conversation = await getJSON('/api/conversations/' + encodeURIComponent(conversationID));
                snapshot = conversation.testingSpecification;
                locked = !!snapshot?.frozen || !!conversation.messages?.length;
                projectID = conversation.projectId || '';
            }
            const draft = chatDrafts.get(scopeKey(conversationID, projectID));
            const spec = draft || snapshot || await projectSpec(projectID);
            if (seq !== openSequence) return;
            const info = locked ? 'frozen' : 'inheritHint';
            showDialog(spec, draft || locked ? 'override' : 'inherit', locked, info, () => {
                setChatDraft(conversationID, projectID, readEditor('task-spec'));
            }, snapshot?.hash);
        } catch (error) { if (seq === openSequence) window.alert(error.message); }
    }
    function currentBatchTasks() { return (el('batch-tasks-input')?.value || '').split('\n').map(line => line.trim()).filter(Boolean); }
    function syncBatchOverrides(tasks) {
        const identity = JSON.stringify(tasks);
        if (identity !== batchMessages) { batchMessages = identity; batchOverrides.clear(); }
    }
    function batchPayload(tasks) {
        syncBatchOverrides(tasks);
        const result = {};
        const spec = readEditor('batch-spec');
        if (spec != null) result.testingSpecification = spec;
        if (batchOverrides.size) result.taskTestingSpecifications = Object.fromEntries(batchOverrides);
        return result;
    }
    function resetBatch() {
        batchOverrides.clear(); batchMessages = '';
        fillEditor('batch-spec', null);
        if (el('batch-spec-mode')) { el('batch-spec-mode').value = 'inherit'; syncEditor('batch-spec'); }
    }
    async function openBatchTask() {
        const tasks = currentBatchTasks();
        if (!tasks.length) return window.alert(tr('enterTasks'));
        syncBatchOverrides(tasks);
        const seq = ++openSequence;
        const select = el('task-spec-task');
        select.replaceChildren(...tasks.map((message, index) => node('option', (index + 1) + '. ' + message.slice(0, 80), { value: String(index) })));
        const identity = JSON.stringify(tasks);
        let choiceSequence = 0;
        let inherited = null;
        async function choose() {
            const choice = ++choiceSequence;
            const index = Number(select.value);
            const isCurrent = () => seq === openSequence && choice === choiceSequence && el('testing-specification-dialog').open && index === Number(select.value);
            el('task-spec-save').disabled = true;
            el('task-spec-mode').disabled = true;
            try {
                const defaultSpec = readEditor('batch-spec') || await projectSpec(el('batch-queue-project-id')?.value);
                if (!isCurrent()) return;
                inherited = defaultSpec;
                const override = batchOverrides.get(index);
                fillEditor('task-spec', override || inherited);
                el('task-spec-mode').value = override ? 'override' : 'inherit';
                el('task-spec-mode').disabled = false;
                el('task-spec-save').disabled = false;
                syncEditor('task-spec');
            } catch (error) { if (isCurrent()) window.alert(error.message); }
        }
        select.onchange = choose;
        showDialog(null, 'inherit', false, 'batchHint', () => {
            if (el('task-spec-save').disabled) throw new Error(tr('loadFailed'));
            if (JSON.stringify(currentBatchTasks()) !== identity) throw new Error(tr('tasksChanged'));
            const index = Number(select.value);
            const spec = readEditor('task-spec');
            if (spec == null) batchOverrides.delete(index); else batchOverrides.set(index, spec);
        });
        el('task-spec-mode').onchange = () => {
            if (el('task-spec-mode').value === 'inherit') fillEditor('task-spec', inherited);
            syncEditor('task-spec');
        };
        select.hidden = false;
        await choose();
    }
    function init() {
        mountEditor('project-spec', 'project-edit-description', false, 'project-settings-specification-target');
        mountEditor('project-modal-spec', 'project-modal-description', false);
        mountEditor('batch-spec', 'batch-queue-project-id', true);
        let projectRequest = 0;
        async function updateBatchDefault() {
            const seq = ++projectRequest;
            if (el('batch-spec-mode')?.value !== 'inherit') return;
            try {
                const spec = await projectSpec(el('batch-queue-project-id')?.value);
                if (seq === projectRequest && el('batch-spec-mode')?.value === 'inherit') fillEditor('batch-spec', spec);
            } catch (error) { window.alert(error.message); }
        }
        el('batch-queue-project-id')?.addEventListener('change', updateBatchDefault);
        el('batch-spec-mode')?.addEventListener('change', updateBatchDefault);
        const leading = document.querySelector('.chat-composer-footer-leading');
        if (leading) {
            const button = node('button', tr('title'), { type: 'button', class: 'testing-specification-button', 'data-i18n': 'testingSpec.title' });
            button.addEventListener('click', () => {
                el('task-spec-task').hidden = true;
                openChat(typeof currentConversationId === 'undefined' ? '' : currentConversationId, typeof getActiveProjectId === 'function' ? getActiveProjectId() : '');
            });
            leading.append(button);
        }
        const batch = el('batch-spec-content')?.closest('details');
        if (batch) {
            const button = node('button', tr('individual'), { type: 'button', class: 'btn-secondary', 'data-i18n': 'testingSpec.individual' });
            button.addEventListener('click', openBatchTask);
            batch.after(button);
        }
        const dialog = node('dialog', '', { id: 'testing-specification-dialog', class: 'testing-specification-dialog', 'aria-labelledby': 'task-spec-heading' });
        dialog.addEventListener('close', () => { openSequence++; dialogSave = null; });
        dialog.append(node('h3', tr('title'), { id: 'task-spec-heading', 'data-i18n': 'testingSpec.title' }));
        dialog.append(node('p', '', { id: 'task-spec-info', class: 'form-hint testing-specification-info' }));
        dialog.append(node('p', '', { id: 'task-spec-hash', class: 'form-hint testing-specification-info', hidden: '' }));
        const taskSelect = node('select', '', { id: 'task-spec-task', class: 'form-input', 'aria-label': tr('selectTask'), 'data-i18n': 'testingSpec.selectTask', 'data-i18n-attr': 'aria-label', 'data-i18n-skip-text': 'true' });
        taskSelect.hidden = true; dialog.append(taskSelect, editor('task-spec', true));
        const actions = node('div', '', { class: 'testing-specification-actions' });
        const cancel = node('button', tr('close'), { type: 'button', class: 'btn-secondary', 'data-i18n': 'testingSpec.close' });
        cancel.addEventListener('click', () => dialog.close());
        const save = node('button', tr('apply'), { id: 'task-spec-save', type: 'button', class: 'btn-primary', 'data-i18n': 'testingSpec.apply' });
        save.addEventListener('click', () => { try { if (dialogSave) dialogSave(); dialog.close(); } catch (error) { window.alert(error.message); } });
        actions.append(cancel, save); dialog.append(actions); document.body.append(dialog);
        if (window.i18nReady) window.i18nReady.then(() => window.applyTranslations?.(document));
        window.addEventListener('logout', () => {
        generation++; openSequence++; projectRequest++;
        resetChat(); resetBatch(); dialogSave = null;
        if (dialog.open) dialog.close();
        ['task-spec', 'project-spec', 'project-modal-spec'].forEach(prefix => fillEditor(prefix, null));
    });
    }
    window.TestingSpecifications = { parseFile, readEditor, fillEditor, setChatDraft, resetChat, applyToChat, acceptChatEvent, batchPayload, resetBatch, openChat, openBatchTask };
    document.addEventListener('DOMContentLoaded', init);
})();
