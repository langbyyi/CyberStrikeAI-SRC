const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('web/static/js/tool-guard.js', 'utf8');
const translations = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8')).toolGuard;

function harness(permissions = ['config:read', 'config:write']) {
    const nodes = new Map();
    class Element {
        constructor(tag = 'div') {
            this.tagName = tag.toUpperCase();
            this.children = [];
            this.listeners = {};
            this.dataset = {};
            this.style = {};
            this.rect = { height: 180 };
            this.attributes = new Map();
            this.classList = { toggle: (name, enabled) => {
                const names = new Set((this.className || '').split(' ').filter(Boolean));
                if (enabled) names.add(name); else names.delete(name);
                this.className = [...names].join(' ');
            } };
            this.value = '';
            this.hidden = false;
            this.open = false;
            this.textContent = '';
        }
        set id(value) { this._id = value; nodes.set(value, this); }
        get id() { return this._id; }
        set innerHTML(_) { throw new Error('Untrusted values must never use innerHTML'); }
        append(...children) { this.children.push(...children); }
        replaceChildren(...children) {
            const detach = (node) => { if (node.id) nodes.delete(node.id); node.children.forEach(detach); };
            this.children.forEach(detach);
            this.children = children;
        }
        addEventListener(type, fn) { this.listeners[type] = fn; }
        setAttribute(name, value) { this.attributes.set(name, String(value)); }
        getAttribute(name) { return this.attributes.get(name) ?? null; }
        removeAttribute(name) { this.attributes.delete(name); }
        focus() { if (!this.disabled) document.activeElement = this; }
        showModal() { this.open = true; }
        close() { this.open = false; if (this.listeners.close) this.listeners.close(); }
        getBoundingClientRect() { return this.rect; }
        scrollIntoView(options) { this.scrolledIntoView = options; }
        querySelectorAll(selector) {
            const tags = selector.split(',').map((tag) => tag.trim().toUpperCase());
            return this.children.flatMap((child) => [
                ...(tags.includes(child.tagName) ? [child] : []), ...child.querySelectorAll(selector)
            ]);
        }
    }
    const document = {
        getElementById: (id) => nodes.get(id),
        createElement: (tag) => new Element(tag),
        activeElement: null,
        addEventListener() {}
    };
    ['rules', 'enabled', 'add', 'save', 'reset', 'test', 'save-state', 'feedback', 'test-result', 'test-tool', 'test-arguments',
        'protection-status', 'rule-count', 'open-test', 'test-panel', 'add-dialog', 'add-confirm', 'add-feedback',
        'add-fields', 'add-test', 'add-body'].forEach((id) => {
        const node = new Element();
        node.id = 'tool-guard-' + id;
    });
    nodes.get('tool-guard-test-tool').value = 'http_request';
    nodes.get('tool-guard-test-arguments').value = '{"url":"https://example.gov.cn"}';
    Object.assign(nodes.get('tool-guard-add-body'), { clientHeight: 500, scrollHeight: 500, scrollTop: 0 });
    const calls = [];
    const queue = [];
    const window = { t: (key) => translations[key.slice('toolGuard.'.length)] || key };
    let newRuleNumber = 0;
    const context = vm.createContext({ window, document, TextEncoder, crypto: { randomUUID: () => 'new-rule-' + ++newRuleNumber },
        hasPermission: (permission) => permissions.includes(permission),
        apiFetch: async (url, options) => {
            calls.push({ url, options });
            if (!queue.length) throw new Error('Unexpected request');
            return queue.shift()();
        }
    });
    vm.runInContext(source, context);
    const reply = (body, ok = true) => queue.push(async () => ({ ok, json: async () => body }));
    const element = (id) => nodes.get('tool-guard-' + id);
    const text = (node) => [node.textContent, ...node.children.map(text)].join('\n');
    return { window, document, reply, queue, calls, element, text };
}

function config() {
    return { enabled: true, rules: [{ id: 'gov', name: 'Government domains', enabled: true,
        pattern: '(?i)\\.gov\\b', message: 'Detected {match}' }] };
}

function fillField(h, id, value) {
    const input = h.element(id);
    assert.ok(input, 'Missing input: ' + id);
    input.value = value;
    input.listeners.input();
}

function fillDraft(h, values = {}) {
    for (const [field, value] of Object.entries({ name: 'New protection', pattern: '(?i)\\.edu',
        message: 'Detected {match} for {rule}', ...values })) {
        fillField(h, 'rule-draft-' + field, value);
    }
}

function runLocal(h, prefix) {
    return h.element(prefix + '-test-run').listeners.click();
}

test('test uses the unsaved configuration and backend RE2 validation without saving or executing tools', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    const pattern = h.element('rule-0-pattern');
    pattern.value = '(?i)\\.gov'; // RE2 inline flag is not valid JavaScript RegExp syntax.
    pattern.listeners.input();
    h.reply({ blocked: true, match: { ruleId: 'gov', ruleName: 'Government domains', matchedText: '.gov', message: 'Detected .gov' } });
    await h.window.testToolGuardConfig();
    assert.equal(h.calls.length, 2);
    assert.equal(h.calls[1].url, '/api/tool-guard/test');
    const body = JSON.parse(h.calls[1].options.body);
    assert.equal(body.config.rules[0].pattern, '(?i)\\.gov');
    assert.deepEqual(body.arguments, { url: 'https://example.gov.cn' });
    assert.match(h.text(h.element('test-result')), /Detected \.gov/);
    assert.equal(h.element('save').disabled, false);
});

test('unsafe rule and match text is rendered as text; messages cannot inject markup', async () => {
    const h = harness();
    const attack = '<img src=x onerror=alert(1)>';
    const initial = config();
    initial.rules[0].name = attack;
    initial.rules[0].message = attack;
    h.reply(initial);
    await h.window.loadToolGuardConfig();
    assert.equal(h.element('rule-0-name').value, attack);
    h.reply({ blocked: true, match: { ruleName: attack, matchedText: attack, message: attack } });
    await h.window.testToolGuardConfig();
    assert.match(h.text(h.element('test-result')), /<img src=x onerror=alert\(1\)>/);
    assert.equal(h.element('test-result').querySelectorAll('img').length, 0);
});

test('draft survives navigation, save errors preserve it, and discard restores last server state', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.changeToolGuardEnabled(false);
    await h.window.loadToolGuardConfig();
    assert.equal(h.calls.length, 1);
    h.reply({ error: 'Invalid RE2 expression' }, false);
    await h.window.saveToolGuardConfig();
    assert.match(h.element('feedback').textContent, /Invalid RE2 expression/);
    assert.equal(h.element('save').disabled, false);
    h.window.resetToolGuardConfig();
    assert.equal(h.element('enabled').checked, true);
    assert.equal(h.element('save').disabled, true);
    assert.equal(h.calls.length, 2);
});

test('successful save explicitly persists enabled and all rule fields through dedicated endpoint', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.changeToolGuardEnabled(false);
    const saved = config();
    saved.enabled = false;
    h.reply(saved);
    await h.window.saveToolGuardConfig();
    assert.equal(h.calls[1].url, '/api/tool-guard');
    assert.equal(h.calls[1].options.method, 'PUT');
    assert.deepEqual(JSON.parse(h.calls[1].options.body), saved);
    assert.equal(h.element('save').disabled, true);
});

test('read-only users can test but cannot mutate the configuration', async () => {
    const h = harness(['config:read']);
    h.reply(config());
    await h.window.loadToolGuardConfig();
    assert.equal(h.element('enabled').disabled, true);
    assert.equal(h.element('rule-0-name').disabled, true);
    h.window.changeToolGuardEnabled(false);
    h.window.addToolGuardRule();
    await h.window.saveToolGuardConfig();
    assert.equal(h.calls.length, 1);
    h.reply({ blocked: false });
    await h.window.testToolGuardConfig();
    assert.equal(JSON.parse(h.calls[1].options.body).config.enabled, true);
});

test('test rejects non-object arguments before making an API request', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    for (const input of ['[]', 'null', '"https://example.gov"', '{']) {
        h.element('test-arguments').value = input;
        await h.window.testToolGuardConfig();
        assert.match(h.element('feedback').textContent, /valid JSON object/);
    }
    assert.equal(h.calls.length, 1);
});

test('stale dry-run responses cannot claim to describe edited rules', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    let finish;
    h.queue.push(() => new Promise((resolve) => { finish = resolve; }));
    const pending = h.window.testToolGuardConfig();
    h.window.changeToolGuardEnabled(false);
    finish({ ok: true, json: async () => ({ blocked: true, match: { matchedText: '.gov' } }) });
    await pending;
    assert.equal(h.element('test-result').hidden, true);
});

test('UTF-8 byte limits are enforced before saving multi-byte rule names', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.element('rule-0-name').value = '政'.repeat(67);
    h.element('rule-0-name').listeners.input();
    await h.window.saveToolGuardConfig();
    assert.equal(h.calls.length, 1);
    assert.match(h.element('feedback').textContent, /200 UTF-8 bytes/);
});

test('malformed dry-run responses report an error instead of claiming the call is allowed', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.reply({});
    await h.window.testToolGuardConfig();
    assert.equal(h.element('test-result').hidden, true);
    assert.match(h.element('feedback').textContent, /invalid test result/);
});

test('saved rules start collapsed behind native accessible buttons without making the configuration dirty', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    const summary = h.element('rule-0-summary');
    assert.equal(summary.tagName, 'BUTTON');
    assert.equal(summary.type, 'button');
    assert.equal(summary.getAttribute('aria-expanded'), 'false');
    assert.equal(summary.getAttribute('aria-controls'), h.element('rule-0-editor').id);
    assert.equal(h.element('rule-0-editor').hidden, true);
    assert.equal(h.element('rule-0-title').textContent, 'Government domains');
    assert.equal(h.element('rule-0-preview').textContent, 'Detected {match}');
    assert.equal(h.element('rule-0-badge').hidden, true);
    summary.listeners.click();
    assert.equal(summary.getAttribute('aria-expanded'), 'true');
    assert.equal(h.element('rule-0-editor').hidden, false);
    summary.listeners.click();
    assert.equal(h.element('rule-0-editor').hidden, true);
    assert.equal(h.element('save').disabled, true);
    assert.equal(h.calls.length, 1);
});

test('only one rule opens at a time and editing updates safe summaries without replacing inputs or losing drafts', async () => {
    const h = harness();
    const initial = config();
    initial.rules.push({ ...initial.rules[0], id: 'second', name: 'Second rule' });
    h.reply(initial);
    await h.window.loadToolGuardConfig();
    h.element('rule-0-summary').listeners.click();
    const input = h.element('rule-0-name');
    input.focus();
    input.value = '<img src=x onerror=alert(1)>';
    input.listeners.input();
    assert.equal(h.element('rule-0-name'), input);
    assert.equal(h.document.activeElement, input);
    assert.equal(h.element('rule-0-title').textContent, input.value);
    assert.equal(h.element('rule-0-badge').hidden, false);
    const reminder = h.element('rule-0-message');
    reminder.value = 'Updated {match} reminder';
    reminder.listeners.input();
    assert.equal(h.element('rule-0-preview').textContent, reminder.value);
    h.element('rule-1-summary').listeners.click();
    assert.equal(h.element('rule-0-editor').hidden, true);
    assert.equal(h.element('rule-1-editor').hidden, false);
    h.element('rule-0-summary').listeners.click();
    assert.equal(h.element('rule-1-editor').hidden, true);
    assert.equal(h.element('rule-0-name').value, input.value);
    assert.equal(h.element('rules').querySelectorAll('img').length, 0);
    h.element('rule-0-close').listeners.click();
    assert.equal(h.document.activeElement, h.element('rule-0-summary'));
    assert.equal(h.element('rule-0-editor').hidden, true);
    const saved = config();
    saved.rules = initial.rules.map((rule, index) => index === 0 ? { ...rule, name: input.value, message: reminder.value } : rule);
    h.reply(saved);
    await h.window.saveToolGuardConfig();
    assert.equal(JSON.parse(h.calls[1].options.body).rules[0].name, input.value);
    assert.equal(h.element('rule-0-editor').hidden, true);
    assert.equal(h.element('rule-0-badge').hidden, true);
});

test('adding a rule opens an isolated dialog; cancellation leaves no phantom row or dirty configuration', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.element('rule-0-summary').listeners.click();
    h.window.addToolGuardRule();
    assert.equal(h.element('add-dialog').open, true);
    assert.equal(h.document.activeElement, h.element('rule-draft-name'));
    assert.equal(h.element('rule-1-editor'), undefined);
    assert.equal(h.element('save').disabled, true);
    fillDraft(h);
    assert.equal(h.element('save').disabled, true);
    h.window.closeToolGuardRuleDialog();
    assert.equal(h.element('add-dialog').open, false);
    assert.equal(h.element('rule-1-editor'), undefined);
    assert.equal(h.element('save').disabled, true);
    assert.equal(h.calls.length, 1);
    h.window.addToolGuardRule();
    assert.equal(h.element('rule-draft-name').value, '');
    assert.equal(h.element('rule-draft-pattern').value, '');
    assert.equal(h.document.activeElement, h.element('rule-draft-name'));
});

test('read-only users can expand and close rule details while all mutation controls stay disabled', async () => {
    const h = harness(['config:read']);
    h.reply(config());
    await h.window.loadToolGuardConfig();
    assert.equal(h.element('rule-0-summary').disabled, false);
    assert.equal(h.element('rule-0-close').disabled, false);
    assert.equal(h.element('rule-0-delete').disabled, true);
    assert.equal(h.element('rule-0-enabled').disabled, true);
    h.element('rule-0-summary').listeners.click();
    assert.equal(h.element('rule-0-editor').hidden, false);
    h.element('rule-0-close').listeners.click();
    assert.equal(h.element('rule-0-editor').hidden, true);
    assert.equal(h.document.activeElement, h.element('rule-0-summary'));
});

test('saving an invalid collapsed draft opens and focuses the first invalid field before any request', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    fillField(h, 'rule-0-name', '');
    fillField(h, 'rule-0-pattern', '');
    await h.window.saveToolGuardConfig();
    assert.equal(h.element('rule-0-editor').hidden, false);
    assert.equal(h.document.activeElement, h.element('rule-0-name'));
    assert.equal(h.element('rule-0-name').getAttribute('aria-invalid'), 'true');
    assert.equal(h.calls.length, 1);
    fillField(h, 'rule-0-name', 'New protection');
    assert.equal(h.element('rule-0-name').getAttribute('aria-invalid'), null);
    h.element('rule-0-close').listeners.click();
    await h.window.testToolGuardConfig();
    assert.equal(h.element('rule-0-editor').hidden, false);
    assert.equal(h.document.activeElement, h.element('rule-0-pattern'));
    assert.equal(h.calls.length, 1);
});

test('backend RE2 errors reveal the affected collapsed rule after controls become writable again', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.element('rule-0-pattern').value = '(';
    h.element('rule-0-pattern').listeners.input();
    h.reply({ error: 'tool guard rule 1 (gov): invalid regular expression: error parsing regexp: missing closing )' }, false);
    await h.window.saveToolGuardConfig();
    assert.equal(h.element('rule-0-editor').hidden, false);
    assert.equal(h.document.activeElement, h.element('rule-0-pattern'));
    assert.equal(h.element('rule-0-pattern').disabled, false);
    assert.equal(h.element('rule-0-pattern').getAttribute('aria-invalid'), 'true');
    assert.equal(h.element('rule-0-pattern').value, '(');
    assert.equal(h.element('save').disabled, false);
});

test('deleting rules maintains the remaining row identity and gives focus to the next summary or add button', async () => {
    const h = harness();
    const initial = config();
    initial.rules.push({ ...initial.rules[0], id: 'second', name: 'Second rule' });
    h.reply(initial);
    await h.window.loadToolGuardConfig();
    h.element('rule-0-summary').listeners.click();
    h.element('rule-0-delete').listeners.click();
    assert.equal(h.element('rule-0-title').textContent, 'Second rule');
    assert.equal(h.document.activeElement, h.element('rule-0-summary'));
    assert.equal(h.element('rule-0-editor').hidden, true);
    h.element('rule-0-summary').listeners.click();
    h.element('rule-0-delete').listeners.click();
    assert.equal(h.document.activeElement, h.element('add'));
    assert.match(h.text(h.element('rules')), /No rules/);
});

test('compact status and enabled counts track draft toggles independently of accordion expansion', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    assert.equal(h.element('protection-status').textContent, translations.protectionOn);
    assert.equal(h.element('rule-count').textContent, translations.ruleCount.replace('{{enabled}}', '1').replace('{{total}}', '1'));
    const toggle = h.element('rule-0-enabled');
    assert.match(toggle.getAttribute('aria-label'), /Government domains/);
    toggle.checked = false;
    toggle.listeners.change();
    assert.equal(h.element('rule-count').textContent, translations.ruleCount.replace('{{enabled}}', '0').replace('{{total}}', '1'));
    assert.equal(h.element('rule-0-editor').hidden, true);
    assert.equal(h.element('rule-0-badge').hidden, false);
    h.window.changeToolGuardEnabled(false);
    assert.equal(h.element('protection-status').textContent, translations.protectionOff);
});


test('single-rule validation opens next to its editor without redirecting to global validation', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.element('rule-0-validate').listeners.click();
    assert.equal(h.element('rule-0-editor').hidden, false);
    assert.equal(h.element('rule-0-test-panel').hidden, false);
    assert.equal(h.element('test-panel').open, false);
    assert.equal(h.document.activeElement, h.element('rule-0-test-arguments'));
    assert.equal(h.element('save').disabled, true);
    assert.equal(h.calls.length, 1);
    h.window.openToolGuardTest();
    assert.equal(h.element('test-panel').open, true);
    assert.equal(h.document.activeElement, h.element('test-arguments'));
    assert.equal(h.element('rule-0-test-panel').hidden, false);
});

test('local validation isolates the current rule from unrelated invalid drafts and displays its result locally', async () => {
    const h = harness();
    const initial = config();
    initial.rules.push({ ...initial.rules[0], id: 'second', name: 'Second rule' });
    h.reply(initial);
    await h.window.loadToolGuardConfig();
    fillField(h, 'rule-0-name', '');
    fillField(h, 'rule-1-pattern', '(?i)\\.edu');
    h.window.openToolGuardTest('second');
    fillField(h, 'rule-1-test-arguments', '{"url":"https://example.edu"}');
    h.reply({ blocked: true, match: { ruleId: 'second', ruleName: 'Second rule', matchedText: '.edu', message: 'Detected .edu' } });
    await runLocal(h, 'rule-1');
    const body = JSON.parse(h.calls[1].options.body);
    assert.deepEqual(body.config.rules, [{ ...initial.rules[1], pattern: '(?i)\\.edu' }]);
    assert.deepEqual(body.arguments, { url: 'https://example.edu' });
    assert.match(h.text(h.element('rule-1-test-result')), /Detected \.edu/);
    assert.equal(h.element('rule-1-test-result').children[0].textContent, translations.singleMatched);
    assert.match(h.element('rule-1-test-result').className, /is-single/);
    assert.equal(h.element('test-result').hidden, true);
    assert.equal(h.element('test-panel').open, false);
    assert.equal(h.element('save').disabled, false);
    await h.window.testToolGuardConfig();
    assert.equal(h.calls.length, 2);
    assert.equal(h.document.activeElement, h.element('rule-0-name'));
});

test('single validation forces flags only in its copied payload while global validation retains order and disabled state', async () => {
    const h = harness();
    const initial = config();
    initial.enabled = false;
    initial.rules[0].enabled = false;
    initial.rules.push({ ...initial.rules[0], id: 'second', name: 'Second rule', enabled: true });
    h.reply(initial);
    await h.window.loadToolGuardConfig();
    h.window.openToolGuardTest('gov');
    h.reply({ blocked: false });
    await runLocal(h, 'rule-0');
    const singleBody = JSON.parse(h.calls[1].options.body);
    assert.equal(singleBody.config.enabled, true);
    assert.deepEqual(singleBody.config.rules, [{ ...initial.rules[0], enabled: true }]);
    assert.equal(h.element('rule-0-test-result').children[0].textContent, translations.singleNotMatched);
    assert.equal(h.element('enabled').checked, false);
    assert.equal(h.element('rule-0-enabled').checked, false);
    assert.equal(h.element('save').disabled, true);
    h.window.openToolGuardTest();
    h.reply({ blocked: false });
    await h.window.testToolGuardConfig();
    assert.deepEqual(JSON.parse(h.calls[2].options.body).config, initial);
    assert.equal(h.element('test-result').children[0].textContent, translations.disabledResult);
    assert.equal(h.element('rule-0-test-result').hidden, false);
    assert.doesNotMatch(h.element('test-result').className, /is-single/);
});

test('local and global validations can run concurrently and keep distinct inputs and results', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.openToolGuardTest('gov');
    fillField(h, 'rule-0-test-tool', 'local_preview');
    fillField(h, 'rule-0-test-arguments', '{"url":"https://example.com"}');
    let finishLocal;
    h.queue.push(() => new Promise((resolve) => { finishLocal = resolve; }));
    const local = runLocal(h, 'rule-0');
    assert.equal(h.element('rule-0-test-run').disabled, true);
    assert.equal(h.element('test').disabled, false);
    h.window.openToolGuardTest();
    h.reply({ blocked: true, match: { ruleId: 'gov', ruleName: 'Government domains', matchedText: '.gov', message: 'Global result' } });
    await h.window.testToolGuardConfig();
    finishLocal({ ok: true, json: async () => ({ blocked: false }) });
    await local;
    assert.equal(JSON.parse(h.calls[1].options.body).toolName, 'local_preview');
    assert.equal(JSON.parse(h.calls[2].options.body).toolName, 'http_request');
    assert.equal(h.element('rule-0-test-result').children[0].textContent, translations.singleNotMatched);
    assert.match(h.text(h.element('test-result')), /Global result/);
    assert.equal(h.element('rule-0-test-run').disabled, false);
    assert.equal(h.element('test').disabled, false);
});

test('editing a local rule or its sample ignores stale successful responses and RE2 errors', async () => {
    for (const target of ['rule-0-pattern', 'rule-0-test-arguments']) {
        for (const ok of [true, false]) {
            const h = harness();
            h.reply(config());
            await h.window.loadToolGuardConfig();
            h.window.openToolGuardTest('gov');
            let finish;
            h.queue.push(() => new Promise((resolve) => { finish = resolve; }));
            const pending = runLocal(h, 'rule-0');
            fillField(h, target, target.endsWith('pattern') ? '(?i)\\.edu' : '{"url":"https://example.edu"}');
            finish({ ok, json: async () => ok ? { blocked: false } :
                { error: 'tool guard rule 1 (gov): invalid regular expression' } });
            await pending;
            assert.equal(h.element('rule-0-test-result').hidden, true);
            assert.equal(h.element('rule-0-test-feedback').hidden, true);
            assert.equal(h.element('rule-0-pattern').getAttribute('aria-invalid'), null);
            assert.equal(h.element('feedback').hidden, true);
            assert.equal(h.element('rule-0-test-run').disabled, false);
        }
    }
});

test('deleting a rule invalidates its pending local response without mislabeling the remaining row', async () => {
    const h = harness();
    const initial = config();
    initial.rules.push({ ...initial.rules[0], id: 'second', name: 'Second rule' });
    h.reply(initial);
    await h.window.loadToolGuardConfig();
    h.window.openToolGuardTest('gov');
    let finish;
    h.queue.push(() => new Promise((resolve) => { finish = resolve; }));
    const pending = runLocal(h, 'rule-0');
    h.element('rule-0-delete').listeners.click();
    finish({ ok: false, json: async () => ({ error: 'tool guard rule 1 (gov): invalid regular expression' }) });
    await pending;
    assert.equal(h.element('rule-0-title').textContent, 'Second rule');
    assert.equal(h.element('rule-0-pattern').getAttribute('aria-invalid'), null);
    assert.equal(h.element('rule-0-test-feedback').hidden, true);
    assert.equal(h.element('feedback').hidden, true);
    assert.equal(h.element('test-panel').open, false);
});

test('local RE2 errors and local required fields focus the selected rule, with no global feedback', async () => {
    const h = harness();
    const initial = config();
    initial.rules.push({ ...initial.rules[0], id: 'second', name: 'Second rule' });
    h.reply(initial);
    await h.window.loadToolGuardConfig();
    fillField(h, 'rule-1-pattern', '(');
    h.window.openToolGuardTest('second');
    h.reply({ error: 'tool guard rule 1 (second): invalid regular expression: error parsing regexp: missing closing )' }, false);
    await runLocal(h, 'rule-1');
    assert.equal(h.element('rule-0-editor').hidden, true);
    assert.equal(h.element('rule-1-editor').hidden, false);
    assert.equal(h.document.activeElement, h.element('rule-1-pattern'));
    assert.equal(h.element('rule-1-pattern').getAttribute('aria-invalid'), 'true');
    assert.equal(h.element('rule-0-pattern').getAttribute('aria-invalid'), null);
    assert.match(h.element('rule-1-test-feedback').textContent, /invalid regular expression/);
    assert.equal(h.element('feedback').hidden, true);
    fillField(h, 'rule-1-name', '');
    await runLocal(h, 'rule-1');
    assert.equal(h.calls.length, 2);
    assert.equal(h.element('rule-1-editor').hidden, false);
    assert.equal(h.document.activeElement, h.element('rule-1-name'));
    assert.equal(h.element('rule-1-name').getAttribute('aria-invalid'), 'true');
});

test('read-only users can validate existing rules but cannot create or commit new rules', async () => {
    const h = harness(['config:read']);
    h.reply(config());
    await h.window.loadToolGuardConfig();
    assert.equal(h.element('rule-0-validate').disabled, false);
    h.element('rule-0-validate').listeners.click();
    h.reply({ blocked: false });
    await runLocal(h, 'rule-0');
    assert.equal(JSON.parse(h.calls[1].options.body).config.rules[0].id, 'gov');
    assert.equal(h.element('rule-0-name').disabled, true);
    h.window.addToolGuardRule();
    await h.window.commitToolGuardRule();
    assert.equal(h.element('add-dialog').open, false);
    assert.equal(h.element('rule-1-summary'), undefined);
    assert.equal(h.calls.length, 2);
    const noRead = harness(['config:write']);
    await noRead.window.loadToolGuardConfig();
    noRead.window.openToolGuardTest('gov');
    await noRead.window.testToolGuardConfig();
    assert.equal(noRead.calls.length, 0);
    assert.equal(noRead.element('test-panel').open, false);
});

test('new rule can be tested before adding without modifying, saving, or opening global validation', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.addToolGuardRule();
    fillDraft(h);
    fillField(h, 'draft-test-arguments', '{"url":"https://example.edu"}');
    h.reply({ blocked: true, match: { ruleId: 'new-rule-1', ruleName: 'New protection', matchedText: '.edu', message: 'Detected .edu for New protection' } });
    await runLocal(h, 'draft');
    assert.equal(h.calls[1].url, '/api/tool-guard/test');
    assert.equal(h.calls[1].options.method, 'POST');
    const body = JSON.parse(h.calls[1].options.body);
    assert.equal(body.config.enabled, true);
    assert.equal(body.config.rules.length, 1);
    assert.equal(body.config.rules[0].name, 'New protection');
    assert.equal(body.config.rules[0].pattern, '(?i)\\.edu');
    assert.match(h.text(h.element('draft-test-result')), /Detected \.edu for New protection/);
    assert.equal(h.element('save').disabled, true);
    assert.equal(h.element('rule-1-summary'), undefined);
    assert.equal(h.element('add-dialog').open, true);
    assert.equal(h.element('test-panel').open, false);
});

test('confirming a new rule validates RE2 on the server and then appends a collapsed unsaved draft', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.addToolGuardRule();
    fillDraft(h);
    // Test-sample mistakes must not prevent adding a valid rule.
    fillField(h, 'draft-test-arguments', '{');
    let finish;
    h.queue.push(() => new Promise((resolve) => { finish = resolve; }));
    const pending = h.window.commitToolGuardRule();
    assert.equal(h.element('rule-1-summary'), undefined);
    assert.equal(h.element('save').disabled, true);
    assert.equal(h.calls[1].url, '/api/tool-guard/test');
    assert.equal(h.calls[1].options.method, 'POST');
    const body = JSON.parse(h.calls[1].options.body);
    assert.equal(body.toolName, 'rule_validation');
    assert.deepEqual(body.arguments, {});
    assert.equal(body.config.rules.length, 1);
    assert.equal(body.config.rules[0].name, 'New protection');
    finish({ ok: true, json: async () => ({ blocked: false }) });
    await pending;
    assert.equal(h.element('add-dialog').open, false);
    assert.equal(h.element('rule-1-title').textContent, 'New protection');
    assert.equal(h.element('rule-1-editor').hidden, true);
    assert.equal(h.element('rule-1-badge').textContent, translations.ruleNew);
    assert.equal(h.element('rule-1-badge').hidden, false);
    assert.equal(h.element('save').disabled, false);
    assert.equal(h.calls.filter(({ options }) => options.method === 'PUT').length, 0);
    h.window.resetToolGuardConfig();
    assert.equal(h.element('rule-1-summary'), undefined);
    assert.equal(h.element('save').disabled, true);
});

test('invalid new-rule RE2 stays in the dialog with focused field and does not append', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.addToolGuardRule();
    fillDraft(h, { pattern: '(' });
    h.reply({ error: 'tool guard rule 1 (new-rule-1): invalid regular expression: error parsing regexp: missing closing )' }, false);
    await h.window.commitToolGuardRule();
    assert.equal(h.element('add-dialog').open, true);
    assert.equal(h.element('rule-draft-pattern').value, '(');
    assert.equal(h.element('rule-draft-pattern').getAttribute('aria-invalid'), 'true');
    assert.equal(h.document.activeElement, h.element('rule-draft-pattern'));
    assert.match(h.element('add-feedback').textContent, /invalid regular expression/);
    assert.equal(h.element('rule-1-summary'), undefined);
    assert.equal(h.element('save').disabled, true);
    assert.equal(h.element('feedback').hidden, true);
});

test('new-rule required-field and byte-limit errors are shown locally before any request', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.addToolGuardRule();
    await h.window.commitToolGuardRule();
    assert.equal(h.document.activeElement, h.element('rule-draft-name'));
    assert.equal(h.element('rule-draft-name').getAttribute('aria-invalid'), 'true');
    fillDraft(h, { name: '政'.repeat(67) });
    await h.window.commitToolGuardRule();
    assert.match(h.element('add-feedback').textContent, /200 UTF-8 bytes/);
    assert.equal(h.calls.length, 1);
    assert.equal(h.element('rule-1-summary'), undefined);
    assert.equal(h.element('save').disabled, true);
});

test('canceling or editing a pending new-rule commit cannot append a stale draft', async () => {
    for (const action of ['close', 'cancel', 'edit']) {
        const h = harness();
        h.reply(config());
        await h.window.loadToolGuardConfig();
        h.window.addToolGuardRule();
        fillDraft(h);
        let finish;
        h.queue.push(() => new Promise((resolve) => { finish = resolve; }));
        const pending = h.window.commitToolGuardRule();
        if (action === 'close') h.window.closeToolGuardRuleDialog();
        else if (action === 'cancel') h.element('add-dialog').listeners.cancel({ preventDefault() {} });
        else fillField(h, 'rule-draft-name', 'Changed while validating');
        finish({ ok: true, json: async () => ({ blocked: false }) });
        await pending;
        assert.equal(h.element('rule-1-summary'), undefined, action);
        assert.equal(h.element('save').disabled, true, action);
        assert.equal(h.element('add-dialog').open, action === 'edit', action);
        if (action === 'edit') assert.equal(h.element('rule-draft-name').value, 'Changed while validating');
    }
});

test('canceled dialog dry-run responses cannot contaminate a reopened new-rule dialog', async () => {
    for (const ok of [true, false]) {
        const h = harness();
        h.reply(config());
        await h.window.loadToolGuardConfig();
        h.window.addToolGuardRule();
        fillDraft(h);
        let finish;
        h.queue.push(() => new Promise((resolve) => { finish = resolve; }));
        const pending = runLocal(h, 'draft');
        h.window.closeToolGuardRuleDialog();
        h.window.addToolGuardRule();
        fillDraft(h, { name: 'Replacement draft', pattern: 'example' });
        finish({ ok, json: async () => ok ? { blocked: false } :
            { error: 'tool guard rule 1 (new-rule-1): invalid regular expression' } });
        await pending;
        assert.equal(h.element('draft-test-result').hidden, true);
        assert.equal(h.element('draft-test-feedback').hidden, true);
        assert.equal(h.element('rule-draft-pattern').getAttribute('aria-invalid'), null);
        assert.equal(h.element('rule-draft-name').value, 'Replacement draft');
        assert.equal(h.element('draft-test-run').disabled, false);
        assert.equal(h.element('save').disabled, true);
    }
});

test('local test errors and unsafe result text stay inside their validation panel', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.addToolGuardRule();
    fillDraft(h);
    for (const input of ['[]', 'null', '"target"', '{']) {
        fillField(h, 'draft-test-arguments', input);
        await runLocal(h, 'draft');
        assert.match(h.element('draft-test-feedback').textContent, /valid JSON object/);
        assert.equal(h.element('feedback').hidden, true);
    }
    assert.equal(h.calls.length, 1);
    fillField(h, 'draft-test-arguments', '{}');
    h.reply({});
    await runLocal(h, 'draft');
    assert.match(h.element('draft-test-feedback').textContent, /invalid test result/);
    assert.equal(h.element('draft-test-result').hidden, true);
    const unsafe = '<img src=x onerror=alert(1)>';
    h.reply({ blocked: true, match: { ruleName: unsafe, matchedText: unsafe, message: unsafe } });
    await runLocal(h, 'draft');
    assert.match(h.text(h.element('draft-test-result')), /<img src=x onerror=alert\(1\)>/);
    assert.equal(h.element('draft-test-result').querySelectorAll('img').length, 0);
});

test('dialog validation keeps one output region through waiting, completion, and stale responses after edits', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.addToolGuardRule();
    const output = h.element('draft-test-output');
    const status = h.element('draft-test-status');
    assert.ok(output);
    assert.equal(status.textContent, translations.testReadyHint);
    assert.equal(status.hidden, false);
    assert.equal(output.getAttribute('aria-busy'), 'false');
    fillDraft(h);

    let finishFirst;
    h.queue.push(() => new Promise((resolve) => { finishFirst = resolve; }));
    const first = runLocal(h, 'draft');
    assert.equal(h.element('draft-test-output'), output);
    assert.equal(status.textContent, translations.testing);
    assert.equal(status.hidden, false);
    assert.equal(output.getAttribute('aria-busy'), 'true');
    assert.equal(h.element('draft-test-result').hidden, true);
    finishFirst({ ok: true, json: async () => ({ blocked: true,
        match: { ruleName: 'New protection', matchedText: '.edu', message: 'Prior result' } }) });
    await first;
    assert.equal(h.element('draft-test-output'), output);
    assert.equal(status.hidden, true);
    assert.equal(output.getAttribute('aria-busy'), 'false');
    assert.match(h.text(h.element('draft-test-result')), /Prior result/);

    let finishStale;
    h.queue.push(() => new Promise((resolve) => { finishStale = resolve; }));
    const stale = runLocal(h, 'draft');
    assert.equal(h.element('draft-test-output'), output);
    assert.equal(status.textContent, translations.testing);
    assert.equal(status.hidden, false);
    assert.equal(h.element('draft-test-result').hidden, true);
    assert.equal(h.element('draft-test-result').children.length, 0);
    fillField(h, 'rule-draft-pattern', '(?i)\\.org');
    assert.equal(status.textContent, translations.testChanged);
    assert.equal(status.hidden, false);
    finishStale({ ok: true, json: async () => ({ blocked: true,
        match: { ruleName: 'New protection', matchedText: '.edu', message: 'Stale result' } }) });
    await stale;
    assert.equal(h.element('draft-test-output'), output);
    assert.equal(status.textContent, translations.testChanged);
    assert.equal(status.hidden, false);
    assert.equal(output.getAttribute('aria-busy'), 'false');
    assert.equal(h.element('draft-test-result').hidden, true);
    assert.equal(h.element('draft-test-feedback').hidden, true);
});

test('clearing a tall dialog result preserves viewport space without retaining its entire height or a historical maximum', async () => {
    const h = harness();
    h.reply(config());
    await h.window.loadToolGuardConfig();
    h.window.addToolGuardRule();
    fillDraft(h);
    h.reply({ blocked: true, match: { ruleName: 'New protection', matchedText: '.edu', message: 'Long result' } });
    await runLocal(h, 'draft');
    const output = h.element('draft-test-output');
    const body = h.element('add-body');
    output.rect = { height: 1200 };
    Object.assign(body, { clientHeight: 600, scrollHeight: 2000, scrollTop: 1000 });
    fillField(h, 'rule-draft-pattern', '(?i)\\.org');
    assert.equal(h.element('draft-test-result').hidden, true);
    assert.equal(output.style.minHeight, '600px');
    assert.equal(body.scrollTop, 1000);

    // Once the shorter content has room below it, further edits release the reserved space.
    output.rect = { height: 600 };
    Object.assign(body, { scrollHeight: 1600, scrollTop: 400 });
    fillField(h, 'draft-test-arguments', '{"url":"https://example.org"}');
    assert.equal(output.style.minHeight, '180px');
    assert.equal(body.scrollTop, 400);
    assert.equal(h.element('draft-test-output'), output);
    assert.equal(h.calls.length, 2);
});
