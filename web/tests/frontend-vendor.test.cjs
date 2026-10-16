const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function browser() {
    const scripts = [];
    const window = {};
    const document = {
        createElement: () => ({ remove() { this.removed = true; } }),
        head: { appendChild: script => scripts.push(script) }
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../static/js/frontend-vendor.js'), 'utf8'), { window, document, setTimeout, clearTimeout });
    return { window, scripts };
}

test('initialization downloads nothing; concurrent requests share one script', async () => {
    const { window, scripts } = browser();
    assert.equal(scripts.length, 0);
    const first = window.loadFrontendVendor('xlsx');
    const second = window.loadFrontendVendor('xlsx');
    assert.equal(first, second);
    assert.equal(scripts.length, 1);
    assert.equal(scripts[0].src, '/static/vendor/xlsx.full.min.js');
    window.XLSX = { utils: {} };
    scripts[0].onload();
    assert.equal(await first, window.XLSX);
    await window.loadFrontendVendor('xlsx');
    assert.equal(scripts.length, 1);
});

test('failure is reported and the next request retries', async () => {
    const { window, scripts } = browser();
    const failure = assert.rejects(window.loadFrontendVendor('elk'), /加载失败/);
    scripts[0].onerror();
    await failure;
    assert.equal(scripts[0].removed, true);
    const retry = window.loadFrontendVendor('elk');
    assert.equal(scripts.length, 2);
    window.elk = function ELK() {};
    scripts[1].onload();
    assert.equal(await retry, window.ELK);
});

test('rejects unknown vendors and successful scripts missing the global', async () => {
    const { window, scripts } = browser();
    await assert.rejects(window.loadFrontendVendor('unknown'), /未知/);
    assert.equal(scripts.length, 0);
    const failure = assert.rejects(window.loadFrontendVendor('xlsx'), /加载失败/);
    scripts[0].onload();
    await failure;
});

test('a pending attack-chain render cannot resume after switching or closing its conversation', async () => {
    const source = fs.readFileSync(path.join(__dirname, '../static/js/chat.js'), 'utf8');
    const start = source.indexOf('async function renderAttackChain(');
    const end = source.indexOf('// 计算图的复杂度', start);
    for (const nextConversation of ['second', null]) {
        let ready;
        const container = { innerHTML: '', isConnected: true };
        const context = {
            window: {}, currentAttackChainConversationId: 'first',
            attackChainCytoscape: null, attackChainOriginalData: null,
            document: { getElementById: () => container },
            loadFrontendVendor: () => new Promise(resolve => { ready = resolve; })
        };
        vm.createContext(context);
        vm.runInContext(source.slice(start, end) + 'window.didRender = true; }', context);
        const rendering = context.renderAttackChain({ nodes: [{}], edges: [] });
        assert.match(container.innerHTML, /loading-spinner/, 'show loading feedback while ELK is pending');
        context.currentAttackChainConversationId = nextConversation;
        ready();
        await rendering;
        assert.equal(context.window.didRender, undefined);
    }
});

test('attack-chain loading and errors wait for asynchronous rendering', async () => {
    const source = fs.readFileSync(path.join(__dirname, '../static/js/chat.js'), 'utf8').replace(/\r\n/g, '\n');
    const start = source.indexOf('async function loadAttackChain(');
    const end = source.indexOf('// 渲染攻击链\nasync function renderAttackChain(', start);
    let finishRender;
    const container = { innerHTML: 'loading-spinner' };
    const button = { disabled: true, style: {} };
    let loading = false;
    let updated = false;
    const context = {
        window: {}, console: { error() {}, log() {} },
        currentAttackChainConversationId: 'synthetic-conversation',
        document: { getElementById: () => container, querySelector: () => button },
        isAttackChainLoading: () => loading,
        setAttackChainLoading: (_, value) => { loading = value; },
        beginAttackChainRequest: () => { context.attackChainRequestSequence++; return context.attackChainRequestSequence; },
        attackChainRequestSequence: 0,
        attackChainRequestOwners: new Map(),
        isCurrentAttackChainRequest: () => true,
        finishAttackChainRequest: () => { loading = false; },
        resetAttackChainContext: () => {},
        apiFetch: async () => ({ ok: true, json: async () => ({ nodes: [{}], edges: [] }) }),
        updateAttackChainStats: () => { updated = true; },
        renderAttackChain: () => new Promise((resolve, reject) => { finishRender = reject; }),
        renderAttackChainError: (el, message) => { el.innerHTML = '<div class="error-message">' + message + '</div>'; },
        attackChainFailureText: (key, fallback, detail) => fallback + (detail || '')
    };
    vm.createContext(context);
    vm.runInContext(source.slice(start, end), context);
    const loadingPromise = context.loadAttackChain('synthetic-conversation');
    await new Promise(setImmediate);
    assert.equal(loading, true, 'keep busy until rendering finishes');
    assert.equal(button.disabled, true);
    assert.equal(updated, false);
    finishRender(new Error('synthetic renderer failure'));
    await loadingPromise;
    assert.equal(loading, false);
    assert.equal(button.disabled, false);
    assert.match(container.innerHTML, /error-message/);
});
