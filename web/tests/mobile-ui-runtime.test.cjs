const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const ApprovalUIModel = require('../static/js/approval-ui-model.js');

function runtime() {
    const source = fs.readFileSync('web/static/js/mobile-ui.js', 'utf8').replace(
        'window.CSAMobile = {',
        'window.CSAMobile = { watchViewport: watchViewport, syncAuthChrome: syncAuthChrome,'
    );
    const classes = new Set();
    const badge = { style: {}, textContent: '' };
    const overlay = { style: { display: 'none' } };
    const events = {};
    const documentEvents = {};
    const window = {
        innerWidth: 390, innerHeight: 844,
        visualViewport: { height: 844, offsetTop: 0, scale: 1, addEventListener() {} },
        matchMedia: () => ({ matches: true }),
        addEventListener: (name, fn) => { events[name] = fn; },
        ApprovalUIModel,
        hasPermission: () => true,
    };
    const document = {
        readyState: 'loading', hidden: false, activeElement: { tagName: 'BODY' },
        querySelector: selector => selector === '#login-overlay' ? overlay : selector === '[data-badge-for="hitl"]' ? badge : null,
        querySelectorAll: () => [],
        documentElement: { clientHeight: 844, style: { setProperty() {}, removeProperty() {} } },
        body: { classList: { toggle: (name, on) => on ? classes.add(name) : classes.delete(name), remove: (...names) => names.forEach(name => classes.delete(name)) } },
        addEventListener: (name, fn) => { documentEvents[name] = fn; },
    };
    const requests = [];
    const context = {
        window, document, console, URLSearchParams,
        setTimeout: fn => { fn(); return 1; }, clearTimeout() {},
        getComputedStyle: node => ({ display: node.style.display }),
        fetch: async url => { requests.push({ url, authenticated: false }); return { ok: false }; },
        apiFetch: async url => { requests.push({ url, authenticated: true }); return { ok: true, json: async () => url.includes('/workflows/') ? ({ runs: [{ id: 'workflow-synthetic' }] }) : ({ total: 237, items: [{ id: 'synthetic' }] }) }; },
    };
    vm.runInNewContext(source.replace('booted: false,', 'booted: true,'), context);
    return { window, document, context, overlay, badge, classes, events, documentEvents, requests, api: window.CSAMobile };
}

test('mobile badge authenticates both sources and uses the unified approval server total', async () => {
    const r = runtime();
    await r.api.refreshHitlBadge();
    assert.deepEqual(r.requests, [
        { url: '/api/approvals?status=pending_human&limit=1&offset=0', authenticated: true },
        { url: '/api/workflows/runs/pending', authenticated: true },
    ]);
    assert.equal(r.badge.textContent, '99+');
});

test('mobile badge ignores a response arriving after logout', async () => {
    const r = runtime();
    const resolvers = [];
    r.context.apiFetch = () => new Promise(done => { resolvers.push(done); });
    const pending = r.api.refreshHitlBadge();
    r.overlay.style.display = 'flex';
    r.api.syncAuthChrome();
    resolvers.forEach(resolve => resolve({ ok: true, json: async () => ({ total: 3, runs: [{ id: 'synthetic' }] }) }));
    await pending;
    assert.equal(r.badge.style.display, 'none');
    assert.equal(r.badge.textContent, '');
});

test('mobile badge refreshes immediately when login overlay closes', async () => {
    const r = runtime();
    r.overlay.style.display = 'flex';
    r.api.syncAuthChrome();
    r.overlay.style.display = 'none';
    r.api.syncAuthChrome();
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(r.requests.length, 2);
});

test('mobile badge includes workflow checkpoints and skips requests forbidden by RBAC', async () => {
    const r = runtime();
    r.window.hasPermission = permission => permission === 'workflow:read';
    await r.api.refreshHitlBadge();
    assert.equal(r.badge.textContent, '1');
    assert.deepEqual(r.requests.map(request => request.url), ['/api/workflows/runs/pending']);
    r.window.hasPermission = () => false;
    await r.api.refreshHitlBadge();
    assert.equal(r.badge.style.display, 'none');
    assert.equal(r.requests.length, 1);
});

test('rotating a focused phone to landscape resets the keyboard height baseline', () => {
    const r = runtime();
    r.api.watchViewport();
    r.document.activeElement = { tagName: 'TEXTAREA' };
    r.window.innerWidth = 667;
    r.window.innerHeight = r.window.visualViewport.height = 375;
    r.events.resize();
    assert.equal(r.classes.has('m-keyboard'), false);
});

test('keyboard hides tabs only with an editable focus and restores them on blur', () => {
    const r = runtime();
    r.api.watchViewport();
    r.window.innerHeight = r.window.visualViewport.height = 500;
    r.events.resize();
    assert.equal(r.classes.has('m-keyboard'), false);
    r.document.activeElement = { tagName: 'TEXTAREA' };
    r.events.resize();
    assert.equal(r.classes.has('m-keyboard'), true);
    r.document.activeElement = { tagName: 'BODY' };
    r.documentEvents.focusout();
    assert.equal(r.classes.has('m-keyboard'), false);
});
