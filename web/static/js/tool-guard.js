(function () {
    'use strict';

    const state = { config: null, saved: null, busy: false, testing: false, revision: 0, openRuleId: null, addDraft: null };
    const ruleViews = new Map();
    const el = (id) => document.getElementById('tool-guard-' + id);
    const canRead = () => typeof hasPermission !== 'function' || hasPermission('config:read');
    const canWrite = () => typeof hasPermission !== 'function' || hasPermission('config:write');
    const copy = (value) => JSON.parse(JSON.stringify(value));

    function tr(key, params) {
        const fullKey = 'toolGuard.' + key;
        const value = typeof window.t === 'function' ? window.t(fullKey, params) : fullKey;
        return String(value).replace(/\{\{(\w+)\}\}/g, (match, name) => params && params[name] !== undefined ? String(params[name]) : match);
    }

    function dirty() {
        return state.config && JSON.stringify(state.config) !== JSON.stringify(state.saved);
    }

    function feedback(message, error) {
        const target = el('feedback');
        if (!target) return;
        target.textContent = message || '';
        target.hidden = !message;
        target.classList.toggle('is-error', !!error);
    }

    function updateControls() {
        const writable = canWrite() && !!state.config && !state.busy;
        const readable = canRead() && !!state.config && !state.busy;
        const isDirty = !!dirty();
        if (el('enabled')) el('enabled').disabled = !writable;
        if (el('add')) el('add').disabled = !writable || state.config.rules.length >= 100;
        if (el('save')) el('save').disabled = !writable || !isDirty;
        if (el('reset')) el('reset').disabled = !writable || !isDirty;
        if (el('test')) el('test').disabled = !canRead() || !state.config || state.busy || state.testing;
        if (el('open-test')) el('open-test').disabled = !readable;
        if (el('save-state')) {
            el('save-state').textContent = state.busy ? tr('loading') : state.config ? tr(isDirty ? 'unsaved' : 'savedState') : '';
            el('save-state').classList.toggle('is-dirty', isDirty);
        }
        if (el('protection-status') && state.config) {
            el('protection-status').textContent = tr(state.config.enabled ? 'protectionOn' : 'protectionOff');
            el('protection-status').classList.toggle('is-off', !state.config.enabled);
        }
        if (el('rule-count') && state.config) el('rule-count').textContent = tr('ruleCount', {
            enabled: state.config.rules.filter((rule) => rule.enabled).length,
            total: state.config.rules.length
        });
        ruleViews.forEach((view) => {
            [view.checkbox, view.remove, ...Object.values(view.fields)].forEach((input) => { input.disabled = !writable; });
            // Reading and collapsing an editor never requires write permission.
            view.summary.disabled = false;
            view.close.disabled = false;
            view.validate.disabled = !readable;
            updateLocalTestControls(view.tester);
            updateRuleView(view);
        });
        if (state.addDraft) {
            const draft = state.addDraft;
            Object.values(draft.fields).forEach((input) => { input.disabled = !writable; });
            el('add-confirm').disabled = !writable || !canRead() || draft.adding;
            el('add-confirm').textContent = tr(draft.adding ? 'addingRule' : 'addToList');
            updateLocalTestControls(draft.tester);
        }
    }

    function invalidateTest() {
        state.revision += 1;
        if (el('test-result')) {
            el('test-result').hidden = true;
            el('test-result').replaceChildren();
        }
    }

    function openTest(ruleId) {
        if (!canRead() || !state.config || state.busy) return;
        if (ruleId !== undefined && ruleId !== null) {
            const view = ruleViews.get(ruleId);
            if (!view) return;
            openRule(ruleId);
            view.tester.root.hidden = false;
            view.validate.setAttribute('aria-expanded', 'true');
            updateRuleView(view);
            view.tester.args.focus();
            return;
        }
        const panel = el('test-panel');
        if (panel) {
            panel.open = true;
            panel.scrollIntoView({ behavior: 'auto', block: 'start' });
        }
        if (el('test-arguments')) el('test-arguments').focus({ preventScroll: true });
    }

    function changed(ruleId) {
        invalidateTest();
        const view = ruleViews.get(ruleId);
        if (view) invalidateLocalTest(view.tester);
        feedback('');
        ruleViews.forEach((view) => Object.values(view.fields).forEach((input) => input.removeAttribute('aria-invalid')));
        updateControls();
    }

    function textElement(tag, text, className) {
        const node = document.createElement(tag);
        node.textContent = text == null ? '' : String(text);
        if (className) node.className = className;
        return node;
    }

    function ruleField(rule, index, key, label, multiline, maxLength, fields, onChange) {
        const field = document.createElement('div');
        field.className = 'tool-guard-field tool-guard-field--' + key;
        const input = document.createElement(multiline ? 'textarea' : 'input');
        input.id = 'tool-guard-rule-' + index + '-' + key;
        input.value = rule[key] || '';
        input.maxLength = maxLength;
        input.spellcheck = false;
        if (multiline) input.rows = 3;
        else input.type = 'text';
        if (key === 'pattern') input.className = 'tool-guard-pattern';
        const labelNode = textElement('label', tr(label));
        labelNode.htmlFor = input.id;
        input.addEventListener('input', () => {
            if (!canWrite() || state.busy) return;
            rule[key] = input.value;
            if (onChange) onChange();
            else changed(rule.id);
        });
        fields[key] = input;
        field.append(labelNode, input);
        if (key === 'message') {
            const hint = textElement('p', tr('messageHint'), 'tool-guard-hint tool-guard-field-hint');
            hint.id = input.id + '-hint';
            input.setAttribute('aria-describedby', hint.id);
            field.append(hint);
        }
        return field;
    }

    function updateRuleView(view) {
        const { rule, card, summary, editor, title, preview, badge, status, checkbox } = view;
        const expanded = state.openRuleId === rule.id;
        const name = rule.name.trim() || tr('unnamedRule');
        title.textContent = name;
        preview.textContent = rule.message.trim() || tr('defaultPreview');
        summary.setAttribute('aria-expanded', String(expanded));
        summary.setAttribute('aria-label', tr(expanded ? 'collapseRule' : 'expandRule') + ': ' + name);
        editor.hidden = !expanded;
        card.classList.toggle('is-expanded', expanded);
        card.classList.toggle('is-disabled', !rule.enabled);
        checkbox.checked = !!rule.enabled;
        checkbox.setAttribute('aria-label', tr('ruleEnabled') + ': ' + name);
        status.textContent = tr(rule.enabled ? 'ruleOn' : 'ruleOff');
        const savedRule = state.saved && state.saved.rules.find((saved) => saved.id === rule.id);
        const modified = !!savedRule && JSON.stringify(savedRule) !== JSON.stringify(rule);
        badge.hidden = !!savedRule && !modified;
        badge.textContent = tr(savedRule ? 'ruleModified' : 'ruleNew');
        view.validate.textContent = tr(view.tester.root.hidden ? 'validateRule' : 'closeRuleTest');
    }

    function openRule(id) {
        state.openRuleId = id;
        ruleViews.forEach(updateRuleView);
    }

    function renderRules() {
        const target = el('rules');
        if (!target || !state.config) return;
        ruleViews.forEach((view) => disposeLocalTest(view.tester));
        target.replaceChildren();
        ruleViews.clear();
        if (!state.config.rules.some((rule) => rule.id === state.openRuleId)) state.openRuleId = null;
        if (!state.config.rules.length) {
            target.append(textElement('p', tr('emptyRules'), 'tool-guard-empty'));
        }
        state.config.rules.forEach((rule, index) => {
            const card = document.createElement('article');
            card.className = 'tool-guard-rule';
            card.id = 'tool-guard-rule-' + index;
            const header = document.createElement('div');
            header.className = 'tool-guard-rule-header';
            const summary = document.createElement('button');
            summary.type = 'button';
            summary.id = card.id + '-summary';
            summary.className = 'tool-guard-rule-summary';
            summary.setAttribute('aria-controls', card.id + '-editor');
            summary.addEventListener('click', () => openRule(state.openRuleId === rule.id ? null : rule.id));
            const overview = document.createElement('span');
            overview.className = 'tool-guard-rule-overview';
            const title = textElement('span', '', 'tool-guard-rule-name');
            title.id = card.id + '-title';
            const preview = textElement('span', '', 'tool-guard-rule-preview');
            preview.id = card.id + '-preview';
            overview.append(title, preview);
            const badge = textElement('span', '', 'tool-guard-rule-badge');
            badge.id = card.id + '-badge';
            const chevron = textElement('span', '›', 'tool-guard-chevron');
            chevron.setAttribute('aria-hidden', 'true');
            summary.append(textElement('span', String(index + 1).padStart(2, '0'), 'tool-guard-rule-number'), overview, badge, chevron);
            const actions = document.createElement('div');
            actions.className = 'tool-guard-rule-actions';
            const toggle = document.createElement('label');
            toggle.className = 'tool-guard-toggle tool-guard-switch';
            const checkbox = document.createElement('input');
            checkbox.id = card.id + '-enabled';
            checkbox.type = 'checkbox';
            checkbox.className = 'theme-checkbox';
            checkbox.checked = !!rule.enabled;
            checkbox.addEventListener('change', () => {
                if (!canWrite() || state.busy) return;
                rule.enabled = checkbox.checked;
                changed(rule.id);
            });
            const status = textElement('span', '');
            toggle.append(checkbox, status);
            actions.append(toggle);
            const editor = document.createElement('div');
            editor.className = 'tool-guard-rule-editor';
            editor.id = card.id + '-editor';
            editor.setAttribute('aria-labelledby', title.id);
            const fields = {};
            const grid = document.createElement('div');
            grid.className = 'tool-guard-editor-grid';
            grid.append(ruleField(rule, index, 'name', 'ruleName', false, 200, fields),
                ruleField(rule, index, 'pattern', 'pattern', true, 4096, fields),
                ruleField(rule, index, 'message', 'message', true, 4096, fields));
            const footer = document.createElement('div');
            footer.className = 'tool-guard-editor-footer';
            const remove = textElement('button', tr('deleteRule'), 'btn-secondary tool-guard-delete');
            remove.id = card.id + '-delete';
            remove.type = 'button';
            remove.addEventListener('click', () => {
                if (!canWrite() || state.busy) return;
                if (state.openRuleId === rule.id) state.openRuleId = null;
                state.config.rules.splice(index, 1);
                renderRules();
                changed();
                const next = state.config.rules[Math.min(index, state.config.rules.length - 1)];
                const focusTarget = next ? ruleViews.get(next.id).summary : el('add');
                if (focusTarget) focusTarget.focus();
            });
            const close = textElement('button', tr('closeEditor'), 'btn-secondary tool-guard-close');
            close.id = card.id + '-close';
            close.type = 'button';
            close.addEventListener('click', () => { openRule(null); summary.focus(); });
            const validate = textElement('button', tr('validateRule'), 'btn-secondary tool-guard-rule-validate');
            validate.id = card.id + '-validate';
            validate.type = 'button';
            const tester = createLocalTest(rule, 'rule-' + index + '-test', fields);
            tester.root.id = card.id + '-test-panel';
            tester.root.classList.toggle('tool-guard-inline-test', true);
            tester.root.hidden = true;
            validate.setAttribute('aria-controls', tester.root.id);
            validate.setAttribute('aria-expanded', 'false');
            validate.addEventListener('click', () => {
                if (!tester.root.hidden) {
                    tester.root.hidden = true;
                    validate.setAttribute('aria-expanded', 'false');
                    updateRuleView(ruleViews.get(rule.id));
                } else openTest(rule.id);
            });
            const editorActions = document.createElement('div');
            editorActions.className = 'tool-guard-editor-actions';
            editorActions.append(validate, close);
            footer.append(remove, editorActions);
            editor.append(grid, footer, tester.root);
            header.append(summary, actions);
            card.append(header, editor);
            ruleViews.set(rule.id, { rule, card, summary, editor, title, preview, badge, status, checkbox, remove, close, validate, fields, tester });
            target.append(card);
        });
        updateControls();
    }

    function render() {
        if (state.config && el('enabled')) el('enabled').checked = !!state.config.enabled;
        renderRules();
        updateControls();
    }

    async function request(url, method, body) {
        const options = { method: method || 'GET' };
        if (body !== undefined) {
            options.headers = { 'Content-Type': 'application/json' };
            options.body = JSON.stringify(body);
        }
        const response = await apiFetch(url, options);
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.error || tr('requestFailed'));
        return result;
    }

    function normalizeConfig(config) {
        if (!config || typeof config.enabled !== 'boolean' || (config.rules != null && !Array.isArray(config.rules))) {
            throw new Error(tr('invalidResponse'));
        }
        return { enabled: config.enabled, rules: (config.rules || []).map((rule) => ({
            id: String(rule.id || ''), name: String(rule.name || ''), enabled: !!rule.enabled,
            pattern: String(rule.pattern || ''), message: String(rule.message || '')
        })) };
    }

    async function loadConfig() {
        if (!el('rules') || !canRead() || state.busy) return;
        // Retain the user's draft when navigating away and back.
        if (dirty() || state.addDraft) { updateControls(); return; }
        state.busy = true;
        feedback('');
        updateControls();
        try {
            const config = normalizeConfig(await request('/api/tool-guard'));
            state.saved = copy(config);
            state.config = config;
            invalidateTest();
            render();
        } catch (error) {
            feedback(tr('loadFailed') + ': ' + error.message, true);
        } finally {
            state.busy = false;
            updateControls();
        }
    }

    function configForRequest(selected = null) {
        if (!state.config) throw new Error(tr('loadFirst'));
        const config = selected ? { enabled: true, rules: [{ ...copy(selected), enabled: true }] } : copy(state.config);
        const utf8 = new TextEncoder();
        for (const [index, rule] of config.rules.entries()) {
            for (const key of ['name', 'pattern', 'message']) {
                let message;
                if (key !== 'message' && !rule[key].trim()) message = tr('requiredFields');
                else if (utf8.encode(rule[key]).length > (key === 'name' ? 200 : 4096)) message = tr('fieldTooLong');
                if (message) {
                    const error = new Error(message);
                    error.ruleIndex = index;
                    error.ruleId = rule.id;
                    error.ruleField = key;
                    throw error;
                }
            }
        }
        // RE2 validation belongs to the backend; JavaScript RegExp has different semantics.
        return config;
    }

    function revealValidationError(error, requestRuleIds) {
        let index = error.ruleIndex;
        let field = error.ruleField;
        if (!Number.isInteger(index)) {
            // The server reports the 1-based rule number for RE2 validation errors.
            const match = /tool guard rule (\d+)(?: \([^\n]*\))?: (.*)/.exec(error.message);
            if (!match) return;
            index = Number(match[1]) - 1;
            field = /^name\b/.test(match[2]) ? 'name' : /^message\b/.test(match[2]) ? 'message' : 'pattern';
        }
        const ruleId = error.ruleId || (requestRuleIds && requestRuleIds[index]);
        const rule = state.config && (ruleId ? state.config.rules.find((item) => item.id === ruleId) : state.config.rules[index]);
        const view = rule && ruleViews.get(rule.id);
        if (!view) return;
        openRule(rule.id);
        const input = view.fields[field];
        if (input) {
            input.setAttribute('aria-invalid', 'true');
            if (input.disabled) view.summary.focus();
            else input.focus();
        }
    }

    async function saveConfig() {
        if (!canWrite() || state.busy || !dirty()) return;
        let failure;
        try {
            const config = configForRequest();
            state.busy = true;
            feedback('');
            updateControls();
            const saved = normalizeConfig(await request('/api/tool-guard', 'PUT', config));
            state.saved = copy(saved);
            state.config = saved;
            invalidateTest();
            render();
            feedback(tr('saveSuccess'));
        } catch (error) {
            failure = error;
            feedback(tr('saveFailed') + ': ' + error.message, true);
        } finally {
            state.busy = false;
            updateControls();
            if (failure) revealValidationError(failure);
        }
    }

    function addRule() {
        if (!canWrite() || !state.config || state.busy) return;
        const dialog = el('add-dialog');
        if (!dialog || state.addDraft) return;
        if (state.config.rules.length >= 100) { feedback(tr('tooManyRules'), true); return; }
        const id = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID() : 'rule-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
        const rule = { id, name: '', enabled: true, pattern: '', message: tr('defaultMessage') };
        const draft = { rule, fields: {}, adding: false, revision: 0, returnFocus: document.activeElement || el('add') };
        state.addDraft = draft;
        const onChange = () => {
            draft.revision += 1;
            invalidateLocalTest(draft.tester);
            showLocalFeedback(el('add-feedback'), '');
            Object.values(draft.fields).forEach((input) => input.removeAttribute('aria-invalid'));
        };
        el('add-fields').replaceChildren(
            ruleField(rule, 'draft', 'name', 'ruleName', false, 200, draft.fields, onChange),
            ruleField(rule, 'draft', 'pattern', 'pattern', true, 4096, draft.fields, onChange),
            ruleField(rule, 'draft', 'message', 'message', true, 4096, draft.fields, onChange)
        );
        draft.tester = createLocalTest(rule, 'draft-test', draft.fields);
        el('add-test').replaceChildren(draft.tester.root);
        showLocalFeedback(el('add-feedback'), '');
        if (!dialog.dataset.guardBound) {
            dialog.dataset.guardBound = 'true';
            dialog.addEventListener('cancel', (event) => { event.preventDefault(); closeRuleDialog(); });
            dialog.addEventListener('close', () => { if (!dialog.open) closeRuleDialog(); });
            dialog.addEventListener('keydown', (event) => {
                if (event.key !== 'Tab') return;
                const controls = Array.from(dialog.querySelectorAll('button, input, textarea'))
                    .filter((input) => !input.disabled && !input.hidden);
                const first = controls[0];
                const last = controls[controls.length - 1];
                if (first && event.shiftKey && document.activeElement === first) {
                    event.preventDefault();
                    last.focus();
                } else if (last && !event.shiftKey && document.activeElement === last) {
                    event.preventDefault();
                    first.focus();
                }
            });
        }
        updateControls();
        dialog.showModal();
        draft.fields.name.focus();
    }

    function closeRuleDialog() {
        const draft = state.addDraft;
        if (!draft) return;
        state.addDraft = null;
        disposeLocalTest(draft.tester);
        const dialog = el('add-dialog');
        if (dialog.open) dialog.close();
        el('add-fields').replaceChildren();
        el('add-test').replaceChildren();
        showLocalFeedback(el('add-feedback'), '');
        updateControls();
        if (draft.returnFocus) draft.returnFocus.focus();
    }

    async function commitRule() {
        const draft = state.addDraft;
        if (!draft || !canWrite() || !canRead() || state.busy || draft.adding) return;
        const revision = draft.revision;
        try {
            if (state.config.rules.length >= 100) throw new Error(tr('tooManyRules'));
            const config = configForRequest(draft.rule);
            draft.adding = true;
            showLocalFeedback(el('add-feedback'), '');
            updateControls();
            // Validate with the same RE2 engine as saving, independently of the optional test inputs.
            const result = await request('/api/tool-guard/test', 'POST', { config, toolName: 'rule_validation', arguments: {} });
            if (state.addDraft !== draft || revision !== draft.revision) return;
            validateTestResult(result);
            state.config.rules.push(copy(draft.rule));
            closeRuleDialog();
            state.openRuleId = null;
            renderRules();
            changed();
            feedback(tr('ruleAdded'));
            const view = ruleViews.get(draft.rule.id);
            if (view) view.summary.focus();
        } catch (error) {
            if (state.addDraft !== draft || revision !== draft.revision) return;
            showLocalFeedback(el('add-feedback'), tr('addFailed') + ': ' + error.message);
            revealLocalError(draft.tester, error);
        } finally {
            draft.adding = false;
            updateControls();
        }
    }

    function resetConfig() {
        if (!canWrite() || state.busy || !state.saved) return;
        closeRuleDialog();
        state.config = copy(state.saved);
        render();
        changed();
    }

    function changeEnabled(enabled) {
        if (!canWrite() || !state.config || state.busy) return;
        state.config.enabled = !!enabled;
        changed();
    }

    function renderTestResult(result, enabled, single, target = el('test-result')) {
        if (!target) return;
        target.replaceChildren();
        target.hidden = false;
        target.classList.toggle('is-blocked', !!result.blocked);
        target.classList.toggle('is-single', !!single);
        target.append(textElement('strong', tr(single ? (result.blocked ? 'singleMatched' : 'singleNotMatched') :
            result.blocked ? 'blocked' : enabled ? 'notBlocked' : 'disabledResult')));
        if (single) target.append(textElement('p', tr('singleResultHint'), 'tool-guard-single-result-hint'));
        if (result.blocked && result.match) {
            const fields = [
                ['matchedRule', result.match.ruleName || result.match.ruleId],
                ['matchedText', result.match.matchedText],
                ['matchedMessage', result.match.message]
            ];
            fields.forEach(([key, value]) => {
                target.append(textElement('p', tr(key), 'tool-guard-result-label'));
                target.append(textElement('pre', value, 'tool-guard-result-value'));
            });
        }
    }

    function showLocalFeedback(target, message) {
        target.textContent = message || '';
        target.hidden = !message;
        target.classList.toggle('is-error', !!message);
    }

    function reserveDialogTestSpace(tester) {
        if (!state.addDraft || state.addDraft.tester !== tester) return;
        const body = el('add-body');
        const bottomSlack = Math.max(0, body.scrollHeight - body.clientHeight - body.scrollTop);
        // Keep only the space needed to avoid clamping the current scroll position.
        // Do not retain an entire long result or accumulate its height across tests.
        const height = Math.max(180, Math.min(body.clientHeight, tester.output.getBoundingClientRect().height - bottomSlack));
        tester.output.style.minHeight = Math.ceil(height) + 'px';
    }

    function invalidateLocalTest(tester, statusKey = 'testChanged') {
        if (!tester) return;
        reserveDialogTestSpace(tester);
        tester.revision += 1;
        tester.result.hidden = true;
        tester.result.replaceChildren();
        showLocalFeedback(tester.feedback, '');
        tester.placeholder.textContent = tr(statusKey);
        tester.placeholder.hidden = false;
    }

    function disposeLocalTest(tester) {
        if (!tester) return;
        tester.disposed = true;
        invalidateLocalTest(tester);
    }

    function updateLocalTestControls(tester) {
        if (!tester) return;
        tester.run.disabled = !canRead() || state.busy || tester.testing || tester.disposed;
        tester.run.textContent = tr(tester.testing ? 'testing' : 'test');
        tester.output.setAttribute('aria-busy', String(tester.testing));
        tester.tool.disabled = !canRead() || state.busy;
        tester.args.disabled = !canRead() || state.busy;
    }

    function createLocalTest(rule, prefix, fields) {
        const root = document.createElement('section');
        root.className = 'tool-guard-local-test';
        const title = textElement('h4', tr('singleTestTitle'));
        title.id = 'tool-guard-' + prefix + '-title';
        root.setAttribute('aria-labelledby', title.id);
        root.append(title, textElement('p', tr('singleTestHint'), 'tool-guard-hint'));
        const tester = { rule, fields, root, revision: 0, testing: false, disposed: false };
        for (const [key, suffix, label, value] of [
            ['tool', 'tool', 'testTool', 'http_request'],
            ['args', 'arguments', 'testArguments', '{"url": "https://example.gov.cn"}']
        ]) {
            const field = document.createElement('div');
            field.className = 'tool-guard-field';
            const input = document.createElement(key === 'tool' ? 'input' : 'textarea');
            input.id = 'tool-guard-' + prefix + '-' + suffix;
            input.value = value;
            input.spellcheck = false;
            if (key === 'tool') { input.type = 'text'; input.maxLength = 512; input.autocomplete = 'off'; }
            else { input.rows = 4; input.className = 'tool-guard-test-arguments'; }
            const labelNode = textElement('label', tr(label));
            labelNode.htmlFor = input.id;
            input.addEventListener('input', () => {
                input.removeAttribute('aria-invalid');
                invalidateLocalTest(tester);
            });
            tester[key] = input;
            field.append(labelNode, input);
            root.append(field);
        }
        tester.run = textElement('button', tr('test'), 'btn-secondary tool-guard-test-run');
        tester.run.id = 'tool-guard-' + prefix + '-run';
        tester.run.type = 'button';
        tester.run.addEventListener('click', () => testLocalRule(tester));
        tester.feedback = textElement('div', '', 'tool-guard-feedback');
        tester.feedback.id = 'tool-guard-' + prefix + '-feedback';
        tester.feedback.hidden = true;
        tester.feedback.setAttribute('role', 'status');
        tester.result = textElement('div', '', 'tool-guard-test-result');
        tester.result.id = 'tool-guard-' + prefix + '-result';
        tester.result.hidden = true;
        tester.result.setAttribute('role', 'status');
        tester.output = textElement('div', '', 'tool-guard-local-output');
        tester.output.id = 'tool-guard-' + prefix + '-output';
        if (prefix === 'draft-test') {
            tester.output.setAttribute('role', 'region');
            tester.output.setAttribute('aria-label', tr('testResultLabel'));
        }
        tester.placeholder = textElement('p', tr('testReadyHint'), 'tool-guard-test-placeholder');
        tester.placeholder.id = 'tool-guard-' + prefix + '-status';
        tester.placeholder.setAttribute('role', 'status');
        tester.output.append(tester.placeholder, tester.feedback, tester.result);
        root.append(tester.run, tester.output);
        updateLocalTestControls(tester);
        return tester;
    }

    function revealLocalError(tester, error) {
        const match = /tool guard rule \d+(?: \([^\n]*\))?: (.*)/.exec(error.message);
        const field = error.ruleField || (match ? /^name\b/.test(match[1]) ? 'name' :
            /^message\b/.test(match[1]) ? 'message' : 'pattern' : null);
        const input = error.input || tester.fields[field];
        if (!input) return;
        input.setAttribute('aria-invalid', 'true');
        // Async feedback stays with its rule instead of reopening another editor.
        if ((state.addDraft && state.addDraft.tester === tester) || state.openRuleId === tester.rule.id) {
            if (!input.disabled) input.focus();
        }
    }

    function validateTestResult(result) {
        if (!result || typeof result.blocked !== 'boolean' || (result.blocked && (!result.match ||
            typeof result.match.matchedText !== 'string' || typeof result.match.message !== 'string'))) {
            throw new Error(tr('invalidTestResponse'));
        }
    }

    async function testLocalRule(tester) {
        if (!canRead() || state.busy || tester.testing || tester.disposed || !state.config) return;
        invalidateLocalTest(tester, 'testing');
        const revision = tester.revision;
        try {
            const config = configForRequest(tester.rule);
            const toolName = tester.tool.value.trim();
            if (!toolName) {
                const error = new Error(tr('toolRequired'));
                error.input = tester.tool;
                throw error;
            }
            let args;
            try {
                args = JSON.parse(tester.args.value);
                if (!args || Array.isArray(args) || typeof args !== 'object') throw new Error();
            } catch (_) {
                const error = new Error(tr('invalidArguments'));
                error.input = tester.args;
                throw error;
            }
            tester.testing = true;
            updateLocalTestControls(tester);
            const result = await request('/api/tool-guard/test', 'POST', { config, toolName, arguments: args });
            if (tester.disposed || revision !== tester.revision) return;
            validateTestResult(result);
            tester.placeholder.hidden = true;
            renderTestResult(result, true, true, tester.result);
        } catch (error) {
            if (tester.disposed || revision !== tester.revision) return;
            tester.placeholder.hidden = true;
            showLocalFeedback(tester.feedback, tr('testFailed') + ': ' + error.message);
            revealLocalError(tester, error);
        } finally {
            tester.testing = false;
            updateLocalTestControls(tester);
        }
    }

    async function testConfig() {
        if (!canRead() || state.busy || state.testing || !state.config) return;
        let revision;
        let requestRuleIds;
        try {
            invalidateTest();
            const config = configForRequest();
            requestRuleIds = config.rules.map((rule) => rule.id);
            const toolName = el('test-tool').value.trim();
            if (!toolName) throw new Error(tr('toolRequired'));
            let args;
            try { args = JSON.parse(el('test-arguments').value); }
            catch (_) { throw new Error(tr('invalidArguments')); }
            if (!args || Array.isArray(args) || typeof args !== 'object') throw new Error(tr('invalidArguments'));
            revision = state.revision;
            state.testing = true;
            feedback('');
            updateControls();
            const result = await request('/api/tool-guard/test', 'POST', { config, toolName, arguments: args });
            if (state.revision !== revision) return;
            validateTestResult(result);
            renderTestResult(result, config.enabled, false);
        } catch (error) {
            if (revision === undefined || revision === state.revision) {
                feedback(tr('testFailed') + ': ' + error.message, true);
                revealValidationError(error, requestRuleIds);
            }
        } finally {
            state.testing = false;
            updateControls();
        }
    }

    window.loadToolGuardConfig = loadConfig;
    window.saveToolGuardConfig = saveConfig;
    window.addToolGuardRule = addRule;
    window.closeToolGuardRuleDialog = closeRuleDialog;
    window.commitToolGuardRule = commitRule;
    window.resetToolGuardConfig = resetConfig;
    window.changeToolGuardEnabled = changeEnabled;
    window.openToolGuardTest = openTest;
    window.testToolGuardConfig = testConfig;
    window.invalidateToolGuardTest = invalidateTest;
    document.addEventListener('languagechange', () => {
        render();
        invalidateTest();
        feedback('');
    });
})();
