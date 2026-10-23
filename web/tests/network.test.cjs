const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../static/js/network.js'), 'utf8');

function runtime() {
    const elements = {};
    const listeners = {};
    class Element {
        constructor(tag = 'div') { this.tagName = tag.toUpperCase(); this.value = ''; this.textContent = ''; this.children = []; this.dataset = {}; this.attributes = {}; this.events = {}; this.style = {}; this.hidden = false; this.disabled = false; this.files = []; this.classList = {toggle() {}}; }
        set id(value) { this._id = value; elements[value] = this; }
        get id() { return this._id; }
        set textContent(value) { this._textContent = String(value); this.children = []; }
        get textContent() { return this._textContent; }
        append(...items) { for (const item of items) { item.parentNode = this; this.children.push(item); } }
        appendChild(item) { this.append(item); }
        showModal() { this.open = true; }
        close() { this.open = false; }
        replaceChildren(...items) { this.children = []; this.append(...items); }
        addEventListener(name, handler) { (this.events[name] ||= []).push(handler); }
        setAttribute(name, value) { this.attributes[name] = String(value); if (name.startsWith('data-')) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = String(value); }
        getAttribute(name) { return this.attributes[name] ?? null; }
        querySelectorAll(selector) { return this.children.flatMap(child => [...(matches(child, selector) ? [child] : []), ...child.querySelectorAll(selector)]); }
        querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
        closest(selector) { return matches(this, selector) ? this : this.parentNode?.closest(selector); }
        async fire(name) { await Promise.all((this.events[name] || []).map(handler => handler({target: this}))); await flush(); }
        click() { return this.fire('click'); }
    }
    function matches(e, selector) { return selector.split(',').some(part => { part = part.trim(); if (part.startsWith('#')) return e.id === part.slice(1); if (part.startsWith('[')) { const [name, raw] = part.slice(1, -1).split('='); return raw ? e.getAttribute(name) === raw.replace(/^['"]|['"]$/g, '') : e.getAttribute(name) !== null; } if (part.startsWith('.')) return (e.className || '').split(' ').includes(part.slice(1)); return e.tagName === part.toUpperCase(); }); }
    const root = new Element();
    for (const id of ['page-projects', 'project-panel-settings']) { const e = new Element(); e.id = id; root.append(e); }
    const pending = [], calls = [];
    const document = {addEventListener(name, callback) {(listeners[name] ||= []).push(callback);}, getElementById: id => root.querySelector('#' + id), createElement: tag => new Element(tag), querySelector: selector => root.querySelector(selector), querySelectorAll: selector => root.querySelectorAll(selector)};
    let allowed = false;
    const context = {window: {apiFetch: (url, options) => {calls.push({url, options}); return new Promise(resolve => pending.push(resolve));}, hasPermission: permission => allowed, confirm: () => true}, document, console, setTimeout, clearTimeout, URL, Blob, TextEncoder, Element, location: {hash: ''}, authScope: 'all', isTokenValid: () => allowed};
    context.window.applyRBACToUI = () => document.querySelectorAll('[data-require-permission]').forEach(e => {e.hidden = !allowed;});
    vm.runInNewContext(source, context);
    return {api: context.window.NetworkTools, elements, pending, calls, root, context, allow(value) {allowed = value;}, async event(name) {for (const fn of listeners[name] || []) await fn(); await flush();}, respond(index, value, ok = true) {pending[index]({ok, status: ok ? 200 : 400, json: async () => value});}};
}
const domText = e => e.textContent + e.children.map(domText).join('');
async function flush() { for (let n = 0; n < 10; n++) await Promise.resolve(); }

test('every pool dialog separates scrollable inputs from its action and result footer', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    for (const name of ['manual', 'subscription', 'source', 'validation', 'edit', 'observation']) {
        const panel=r.elements['network-'+name+'-dialog'];
        const body=panel.querySelector('.network-dialog-body'), footer=panel.querySelector('.network-dialog-footer');
        assert.ok(body, name+' must keep form inputs in its scrolling body');
        assert.ok(footer, name+' must keep actions visible below its scrolling body');
        assert.equal(panel.getAttribute('aria-labelledby'), panel.id+'-title');
        assert.ok(footer.querySelector('button'), name+' footer has no action');
        assert.ok(footer.querySelector('#'+panel.id+'-message'), name+' result is outside the footer');
    }
    assert.ok(r.elements['network-job-pause'].closest('.network-task-bar'));
    assert.equal(r.elements['network-task-progress'].tagName, 'PROGRESS');
});

test('pool jobs expose pause and resume while showing committed collection progress', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const remembered = new Map();
    r.context.window.sessionStorage = {getItem: key => remembered.get(key) || null, setItem: (key, value) => remembered.set(key, value), removeItem: key => remembered.delete(key)};
    assert.ok(r.elements['network-job-pause']);
    const open = r.elements['network-open-sources'].click(); await flush(); r.respond(0, {providers:[{kind:'fofa',configured:true}]}); await open;
    const crawl=r.elements['network-source-crawl'].click();await flush();r.respond(1,{id:'source'});await flush();r.respond(2,{job_id:'job'});await flush();
    r.respond(3,{state:'running',pausable:true,progress:{kind:'source',pages:1,imported:2,skipped:0,completed:0}});await flush();
    assert.match(r.elements['network-job-status'].textContent,/2/);
    assert.equal(r.elements['network-source-dialog-message'].textContent, '', 'running state belongs in the progress strip, not a stale result notice');
    r.respond(4,{error:'temporary refresh failure'},false);await flush();
    assert.equal(remembered.get('network-pool-job'), 'job');
    assert.equal(r.elements['network-job-pause'].hidden, false);
    const pause=r.elements['network-job-pause'].click();await flush();assert.equal(r.calls[5].url,'/api/network/jobs/job/pause');r.respond(5,{state:'paused'});await pause;
    assert.equal(r.elements['network-job-pause'].textContent,'继续');
    const resume=r.elements['network-job-pause'].click();await flush();assert.equal(r.calls[6].url,'/api/network/jobs/job/resume');r.respond(6,{state:'running'});await resume;
    await new Promise(resolve=>setTimeout(resolve,1100));r.respond(7,{state:'completed',result:{imported:2,skipped:0}});await flush();r.respond(8,{nodes:[]});await crawl;
    assert.equal(remembered.has('network-pool-job'), false);
});

test('reopening the pool restores a paused job and resumes without submitting a new job', async () => {
    const r = runtime(); r.allow(true);
    const remembered = new Map([['network-pool-job', 'paused-job']]), timers = [];
    let now = 10000;
    r.context.Date = class extends Date {static now() { return now; }};
    r.context.window.sessionStorage = {getItem: key => remembered.get(key) || null, setItem: (key, value) => remembered.set(key, value), removeItem: key => remembered.delete(key)};
    r.context.setTimeout = fn => {timers.push(fn); return timers.length;};
    const opening = r.api.openPool(); r.respond(0, {nodes: []}); await opening;
    r.respond(1, {target: 'https://www.baidu.com'});
    assert.equal(r.calls[2].url, '/api/network/jobs/paused-job');
    r.respond(2, {state:'paused',pausable:true,progress:{kind:'source',pages:1,imported:2,skipped:0}}); await flush();
    r.respond(3, {error:'temporary refresh failure'}, false); await flush();
    assert.equal(r.elements['network-job-pause'].textContent, '继续');
    now += 2000; timers.shift()(); await flush();
    r.respond(4, {state:'paused',pausable:true,progress:{kind:'source',pages:1,imported:2,skipped:0}}); await flush();
    assert.equal(r.calls[5].url, '/api/network/proxies?target=https%3A%2F%2Fwww.baidu.com');
    r.respond(5, {nodes: []}); await flush();
    assert.match(r.elements['network-job-status'].textContent, /已暂停/);
    const resuming = r.elements['network-job-pause'].click(); await flush();
    assert.equal(r.calls[6].url, '/api/network/jobs/paused-job/resume');
    r.respond(6, {state:'running'}); await resuming;
    timers.shift()(); await flush(); r.respond(7, {state:'completed',result:{imported:2,skipped:0}}); await flush();
    r.respond(8, {nodes: []}); await flush();
    assert.equal(remembered.has('network-pool-job'), false);
    assert.equal(r.elements['network-job-pause'].hidden, true);
});

test('diagnosis completion remains visible after progress refreshes the pool', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    r.elements['network-target'].value = 'https://example.test';
    const nodes = [{id:'node-1',address:'http://127.0.0.1:8081',enabled:true}];
    const loading=r.api.loadPool(); r.respond(0,{nodes}); await loading;
    const checking=r.elements['network-rows'].querySelectorAll('button').find(e=>e.textContent==='验证').click();await flush();
    r.respond(1,{job_id:'job'});await flush();
    r.respond(2,{state:'completed',pausable:true,progress:{kind:'validation',total:1,completed:1,passed:1,failed:0},result:[{node_id:'node-1',reachable:true,http_status:200}]});await flush();
    assert.equal(r.elements['network-task-progress'].max, 1);
    assert.equal(r.elements['network-task-progress'].value, 1);
    r.respond(3,{nodes});await flush();
    assert.match(r.elements['network-message'].textContent,/node-1/);
    r.respond(4,{nodes});await checking;
});

test('pool heading counts all nodes and selected rows stay marked through filtering', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool();
    r.respond(0, {nodes: [{id: 'a', address: 'http://192.0.2.1:8080', enabled: true}, {id: 'b', address: 'http://192.0.2.2:8080', enabled: false}]}); await loading;
    assert.equal(r.elements['network-pool-count'].textContent, '共 2 个节点');
    const row = r.elements['network-rows'].children[0]; assert.equal(row.dataset.networkSelected, 'false');
    r.elements['network-select-a'].checked = true; await r.elements['network-select-a'].fire('change');
    assert.equal(row.dataset.networkSelected, 'true');
    r.elements['network-filter'].value = '192.0.2.2'; await r.elements['network-filter'].fire('input');
    assert.equal(r.elements['network-pool-count'].textContent, '共 2 个节点');
    r.elements['network-filter'].value = ''; await r.elements['network-filter'].fire('input');
    assert.equal(r.elements['network-rows'].children[0].dataset.networkSelected, 'true');
    r.elements['network-select-a'].checked = false; await r.elements['network-select-a'].fire('change');
    assert.equal(r.elements['network-rows'].children[0].dataset.networkSelected, 'false');
});

test('language changes keep validation details clickable', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool(); r.respond(0, {nodes: [{id: 'a', address: 'http://192.0.2.1:8080', enabled: true}], pool_observations: {a: {reachable: false, latency_ms: 5000, reason: 'synthetic timeout'}}}); await loading;
    const cell = r.elements['network-rows'].children[0].children[6];
    const trigger = cell.querySelector('button'); assert.ok(trigger);
    await r.event('languagechange');
    assert.equal(cell.querySelector('button') === trigger, true);
    await trigger.click();
    assert.equal(r.elements['network-observation-dialog'].open, true);
    assert.match(r.elements['network-observation-details'].value, /synthetic timeout/);
});
function project(policy = {}, bindings = []) { return {policy: {mode: 'auto', version: 1, ...policy}, scope: {targets: ['*.example.test']}, vpn: {state: 'stopped'}, bindings, platform: 'linux'}; }

test('saving ordinary network settings never promotes assessed targets to declared policy',async()=>{
 const r=runtime();r.allow(true);
 const data={...project({mode:'fixed_proxy',targets:[]}),declared_scope:{targets:[]},scope:{targets:['api.backend.test']}};
 await loadedProject(r,'A',data);
 assert.equal(r.elements['project-network-targets'].value,'');
 r.elements['project-network-dns'].value='192.0.2.53';
 const index=r.calls.length;
 const saving=r.elements['project-network-card'].querySelectorAll('button').find(e=>e.textContent==='保存网络配置').click();
 await flush();
 assert.deepEqual(JSON.parse(r.calls[index].options.body).targets,[]);
 r.respond(index,{policy:data.policy});await flush();r.respond(index+1,data);await saving;
});
test('page size changes reset pagination while preserving selected nodes', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool(); r.respond(0, {nodes: Array.from({length: 65}, (_, i) => ({id: 'n' + i, address: 'http://127.0.0.1:' + (8000 + i), enabled: true}))}); await loading;
    r.elements['network-select-n0'].checked = true; await r.elements['network-select-n0'].fire('change');
    await r.elements['network-page-next'].click();
    const size = r.elements['network-page-size']; assert.ok(size); assert.deepEqual(size.children.map(o => o.value), ['20', '50', '100', '200', '500']); size.value = '50'; await size.fire('change');
    assert.equal(r.elements['network-rows'].children.length, 50);
    assert.equal(r.elements['network-page-previous'].disabled, true);
    assert.equal(r.elements['network-select-n0'].checked, true);
    size.value = '500'; await size.fire('change'); assert.equal(r.elements['network-rows'].children.length, 65);
    size.value = 'invalid'; await size.fire('change'); assert.equal(size.value, '500');
});

test('node editing uses a dialog without changing enabled state or expanding table cells', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool(); r.respond(0, {nodes: [{id: 'one', address: 'socks5://192.0.2.1:1080', source: 'source:opaque-id', enabled: true}]}); await loading;
    const row = r.elements['network-rows'].children[0]; assert.notEqual(row.children[7].className, 'network-actions');
    assert.doesNotMatch(row.children[2].textContent, /opaque-id/);
    await row.querySelectorAll('button').find(b => b.textContent === '编辑').click();
    const panel = r.elements['network-edit-dialog'], input = r.elements['network-edit-address']; assert.equal(panel.open, true); assert.equal(input.value, '');
    input.value = 'socks5://user:secret@192.0.2.2:1080';
    const saving = r.elements['network-edit-save'].click(); await flush();
    assert.deepEqual(JSON.parse(r.calls[1].options.body), {address: input.value});
    r.respond(1, {}); await flush(); r.respond(2, {nodes: []}); await saving;
    assert.equal(panel.open, false); assert.equal(input.value, '');
});

test('delete all ignores display filters, batches global nodes, and reports protected skips', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    r.elements['network-filter'].value = 'unmatched'; r.elements['network-target'].value = 'https://example.test';
    let confirmation; r.context.window.confirm = value => { confirmation = value; return true; };
    const deleting = r.elements['network-delete-all'].click(); await flush(); assert.equal(r.calls[0].url, '/api/network/proxies');
    const nodes = Array.from({length: 1001}, (_, i) => ({id: 'global-' + i})); r.respond(0, {nodes}); await flush();
    assert.match(confirmation, /1001/); assert.equal(JSON.parse(r.calls[1].options.body).node_ids.length, 1000);
    assert.equal(JSON.parse(r.calls[1].options.body).action, 'delete');
    r.respond(1, {updated: 999, skipped: 1}); await flush(); assert.deepEqual(JSON.parse(r.calls[2].options.body).node_ids, ['global-1000']);
    r.respond(2, {updated: 1, skipped: 0}); await flush(); r.respond(3, {nodes: []}); await deleting;
    assert.match(r.elements['network-message'].textContent, /1000.*1/);
});

test('canceling delete all and lacking admin permission never deletes nodes', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded'); r.context.window.confirm = () => false;
    const deleting = r.elements['network-delete-all'].click(); await flush(); r.respond(0, {nodes: [{id: 'keep'}]}); await deleting;
    assert.equal(r.calls.length, 1);
    r.allow(false); await r.elements['network-delete-all'].click(); assert.equal(r.calls.length, 1);
});
async function loadedProject(r, id, data = project()) {r.allow(true); const index = r.calls.length; const load = r.api.loadProject(id); r.respond(index, data); await load;}

function installProjectSelector(r) {
    const projects = fs.readFileSync(path.join(__dirname, '../static/js/projects.js'), 'utf8');
    for (const id of ['project-edit-name', 'project-edit-description', 'project-edit-scope']) {
        const input = r.context.document.createElement('input'); input.id = id; r.root.append(input);
    }
    r.context.apiFetch = r.context.window.apiFetch;
    for (const name of ['setActiveProjectId', 'syncAllProjectsFilterSelects', 'renderProjectsSidebar', 'updateProjectsDetailVisibility', 'renderProjectDetailTitle', 'updateProjectStatusPill', 'renderProjectDetailMeta', 'renderProjectDetailDesc', 'refreshProjectHeaderStats', 'switchProjectTab']) r.context[name] = () => {};
    vm.runInNewContext(projects.slice(0, projects.indexOf('function tp(')) + projects.slice(projects.indexOf('async function selectProject(id)'), projects.indexOf('function switchProjectTab(tab)')), r.context);
}

test('selecting another project immediately disables the previous project network form', async () => {
    const r = runtime(); await loadedProject(r, 'A'); installProjectSelector(r);
    const selecting = r.context.selectProject('B'); await flush();
    assert.equal(r.elements['project-network-targets'].value, '');
    assert.equal(r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '保存网络配置').disabled, true);
    r.respond(r.calls.findIndex(call => call.url === '/api/projects/B'), {id: 'B', name: 'B'}); await selecting;
    r.respond(r.calls.findIndex(call => call.url === '/api/projects/B/network-policy'), project()); await flush();
});

test('out-of-order project selection cannot change the network card or save destination', async () => {
    const r = runtime(); r.allow(true); installProjectSelector(r);
    const first = r.context.selectProject('A'), second = r.context.selectProject('B'); await flush();
    r.respond(r.calls.findIndex(call => call.url === '/api/projects/B'), {id: 'B', name: 'B'}); await second;
    r.respond(r.calls.findIndex(call => call.url === '/api/projects/B/network-policy'), project({targets: ['b.example.test']})); await flush();
    r.respond(r.calls.findIndex(call => call.url === '/api/projects/A'), {id: 'A', name: 'A'}); await first;
    r.respond(r.calls.findIndex(call => call.url === '/api/projects/A/network-policy'), project({targets: ['a.example.test']})); await flush();
    assert.equal(vm.runInNewContext('currentProjectId', r.context), 'B');
    assert.equal(r.elements['project-network-targets'].value, 'b.example.test');
    assert.equal(r.elements['project-edit-name'].value, 'B');
    const saveIndex = r.calls.length;
    const saving = r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '保存网络配置').click(); await flush();
    assert.equal(r.calls[saveIndex].url, '/api/projects/B/network-policy'); assert.equal(r.calls[saveIndex].options.method, 'PUT');
    r.respond(saveIndex, {}); await flush(); r.respond(saveIndex + 1, project({targets: ['b.example.test']})); await saving;
});

test('a successful refresh recovers the form and clears an initial project load error', async () => {
    const r = runtime(); r.allow(true); const loading = r.api.loadProject('A');
    r.respond(0, {error: 'temporary read failure'}, false); await loading;
    const refreshing = r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '刷新状态').click(); await flush();
    r.respond(1, project({mode: 'fixed_vpn', vpn_profile_id: 'profile', targets: ['api.example.test']})); await refreshing;
    assert.equal(r.elements['project-network-mode'].disabled, false);
    assert.equal(r.elements['project-network-mode'].value, 'fixed_vpn');
    assert.equal(r.elements['project-network-targets'].value, 'api.example.test');
    assert.equal(r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '保存网络配置').disabled, false);
    assert.equal(r.elements['project-network-message'].textContent, '');
});

test('a background refresh cannot undo a newer asset change in the same project', async () => {
    const r = runtime(), timers = [];
    r.context.document.visibilityState = 'visible'; r.elements['project-panel-settings'].getClientRects = () => [1];
    r.context.setTimeout = fn => {timers.push(fn); return timers.length;}; r.context.clearTimeout = () => {};
    const old = project({mode: 'fixed_vpn', vpn_profile_id: 'profile'}, [{target: 'api.example.test', source: 'agent', excluded: false}]);
    await loadedProject(r, 'A', old);
    const polling = timers.shift()(); await flush();
    const excluding = r.elements['project-network-bindings'].querySelector('button').click(); await flush();
    r.respond(2, {}); await flush();
    r.respond(3, project({mode: 'fixed_vpn', vpn_profile_id: 'profile'}, [{target: 'api.example.test', source: 'user', excluded: true}])); await excluding;
    r.respond(1, {...old, vpn: {state: 'ready'}}); await polling;
    assert.match(r.elements['project-network-bindings'].children[0].children[0].textContent, /已排除/);
    assert.match(r.elements['project-network-status'].textContent, /已断开/);
});

test('global pool describes shared proxies and keeps VPN controls inside project settings', async () => {
    const r = runtime(); await r.event('DOMContentLoaded');
    const pool = r.elements['page-network'];
    assert.doesNotMatch(pool.querySelector('.page-header').children[1].textContent, /VPN/i);
    await loadedProject(r, 'A', project({mode: 'fixed_vpn', vpn_profile_id: 'project-profile'}));
    assert.equal(pool.querySelector('#project-network-card'), null);
    assert.equal(pool.querySelectorAll('input').filter(e => e.type === 'file').length, 0);
    assert.ok(r.elements['project-network-config'].closest('#project-panel-settings'));
    assert.ok(r.elements['project-network-password'].closest('#project-panel-settings'));
});

test('late pool response does not overwrite a newer target result', async () => {
    const r = runtime(); await r.event('DOMContentLoaded');
    r.elements['network-target'].value = 'https://first.test'; const first = r.api.loadPool();
    r.elements['network-target'].value = 'https://second.test'; const second = r.api.loadPool();
    r.respond(1, {nodes: [{id: 'second', address: 'http://127.0.0.1:8082', enabled: true, eligible: true}]}); await second;
    const rows = r.elements['network-rows'].children;
    r.respond(0, {nodes: [{id: 'first', address: 'http://127.0.0.1:8081', enabled: true, eligible: true}]}); await first;
    assert.strictEqual(r.elements['network-rows'].children, rows); assert.equal(rows[0].children[1].textContent, 'http://127.0.0.1:8082');
});
test('target input handles ordinary lines and existing project scope JSON', () => {
    const {api} = runtime(); assert.equal(JSON.stringify(api.parseTargets('example.test\n*.example.test\n10.0.0.0/24')), JSON.stringify(['example.test', '*.example.test', '10.0.0.0/24']));
    assert.equal(JSON.stringify(api.parseTargets('{"targets":["https://example.test"],"exclude":[]}')), JSON.stringify(['https://example.test'])); assert.throws(() => api.parseTargets('{broken'));
});
test('first login reveals existing admin forms after RBAC refresh', async () => {
    const r = runtime(); await r.event('DOMContentLoaded');
    assert.ok(r.elements['network-import'], 'create the form before authentication finishes');
    const form = r.elements['network-import']; const container = form.closest('[data-require-permission]');
    assert.equal(container.hidden, true);
    r.allow(true); r.context.window.applyRBACToUI();
    assert.equal(container.hidden, false); assert.strictEqual(r.elements['network-import'], form);
});
test('pool errors remain visible on the page', async () => {
    const r = runtime(); const opening = r.api.openPool(); r.respond(0, {error: 'proxy listing failed'}, false); await opening;
    assert.match(r.elements['network-message'].textContent, /proxy listing failed/);
});

test('empty manual import is rejected without sending a request', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    await r.elements['network-open-manual'].click();
    r.elements['network-import'].value = '   \n';
    const saving = r.elements['network-manual-dialog'].querySelectorAll('button').find(e => e.textContent === '导入').click();
    await flush();
    assert.equal(r.calls.length, 0);
    await saving;
    assert.match(r.elements['network-manual-dialog-message'].textContent, /请填写/);
});

test('dialog interior padding stays open and only the backdrop dismisses it', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    await r.elements['network-open-manual'].click();
    const panel = r.elements['network-manual-dialog'];
    panel.getBoundingClientRect = () => ({left: 100, top: 100, right: 600, bottom: 500});
    const click = panel.events.click[0];
    click({target: panel, clientX: 105, clientY: 200});
    assert.equal(panel.open, true);
    click({target: panel, clientX: 80, clientY: 200});
    assert.equal(panel.open, false);
});

test('crawler shows missing engine credentials before saving a source and supports subscription without API keys', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const opening = r.elements['network-open-sources'].click(); await flush();
    assert.equal(r.calls[0]?.url, '/api/network/sources');
    r.respond(0, {sources: [], providers: [{kind: 'fofa', configured: false}, {kind: 'quake', configured: true}, {kind: 'subscription', configured: true}]}); await opening;
    assert.equal(r.elements['network-source-crawl'].disabled, true);
    assert.match(r.elements['network-source-provider-status'].textContent, /FOFA.*系统设置/);
    const kind = r.elements['network-source-kind'];
    kind.value = 'quake'; await kind.fire('change');
    assert.equal(r.elements['network-source-crawl'].disabled, false);
    assert.match(r.elements['network-source-provider-status'].textContent, /Quake.*已配置/);
    kind.value = 'subscription'; await kind.fire('change');
    assert.equal(r.elements['network-source-crawl'].disabled, false);
    assert.match(r.elements['network-source-provider-status'].textContent, /不需要.*API/);
});

test('provider configuration failure can be retried without losing a custom query', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    r.elements['network-source-query'].value = 'ip="192.0.2.5"';
    const first = r.elements['network-open-sources'].click(); await flush();
    assert.equal(r.elements['network-source-crawl'].disabled, true);
    r.respond(0, {message: 'temporary configuration read failure'}, false); await first;
    assert.match(r.elements['network-source-provider-status'].textContent, /重新打开/);
    assert.equal(r.elements['network-source-crawl'].disabled, true);
    const second = r.elements['network-open-sources'].click(); await flush();
    r.respond(1, {providers: [{kind: 'fofa', configured: true}]}); await second;
    assert.equal(r.elements['network-source-query'].value, 'ip="192.0.2.5"');
    assert.equal(r.elements['network-source-crawl'].disabled, false);
});

test('an older crawl cannot re-enable a provider rejected when the dialog reopens', async () => {
    for (const failedRead of [false, true]) {
        const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
        const opening = r.elements['network-open-sources'].click(); await flush();
        r.respond(0, {providers: [{kind: 'fofa', configured: true}]}); await opening;
        const crawling = r.elements['network-source-crawl'].click(); await flush();
        r.elements['network-source-dialog'].close();
        const reopen = r.elements['network-open-sources'].click(); await flush();
        r.respond(2, failedRead ? {message: 'temporary read failure'} : {providers: [{kind: 'fofa', configured: false}]}, !failedRead); await reopen;
        r.respond(1, {message: 'save failed'}, false); await crawling;
        assert.equal(r.elements['network-source-crawl'].disabled, true);
        await r.elements['network-source-crawl'].click();
        assert.equal(r.calls.length, 3);
    }
});

test('crawl rejects zero and fractional limits before saving configuration', async () => {
    for (const value of ['0', '-1', '1.5', '10001', '']) {
        const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
        r.elements['network-source-limit'].value = value;
        const crawling = r.elements['network-source-crawl'].click(); await flush();
        assert.equal(r.calls.length, 0, 'invalid limit was submitted: ' + value);
        await crawling;
        assert.match(r.elements['network-message'].textContent, /1.*10000/);
    }
});

test('structured API failures display their readable message', async () => {
	const r = runtime(); const opening = r.api.openPool();
	r.respond(0, {error: 'network_forbidden', message: 'Readable network permission failure'}, false); await opening;
	assert.equal(r.elements['network-message'].textContent, 'Readable network permission failure');
});
test('upload started for A cannot upload after switching to project B', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({mode: 'fixed_vpn', vpn_profile_id: 'old'}));
    let finishCertificate;
    r.elements['project-network-config'].files = [{name: 'client.ovpn', size: 10, text: async () => 'profile A'}];
    r.elements['project-network-certificates'].files = [{name: 'a.key', size: 10, text: () => new Promise(resolve => {finishCertificate = resolve;})}];
    const save = r.elements['project-network-card'].querySelectorAll('button').find(e => /保存网络/.test(e.textContent)).click(); await flush();
    await loadedProject(r, 'B'); finishCertificate('key A'); await save; await flush();
    assert.equal(r.calls.filter(c => c.options?.method === 'POST').length, 0, 'stale upload must stop before sending secrets');
    assert.doesNotMatch(r.elements['project-network-message'].textContent, /已保存/);
});
test('binding failures are shown inside the project card', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({}, [{target: 'api.example.test', source: 'agent', excluded: false}]));
    const click = r.elements['project-network-bindings'].querySelector('button').click(); await flush(); r.respond(1, {error: 'binding denied'}, false); await click;
    assert.equal(r.elements['project-network-message'].textContent, 'binding denied');
});

test('expired semantic bindings show that Agent reassessment is required',async()=>{
 const r=runtime();await loadedProject(r,'A',project({},[{target:'api.backend.test',source:'agent',excluded:false,scope_state:'needs_reassessment'}]));
 assert.match(domText(r.elements['project-network-bindings']),/待 Agent 重新判断/);
 assert.doesNotMatch(domText(r.elements['project-network-bindings']),/已关联/);
});

test('successful asset retry clears the old error without clearing network drafts', async () => {
    for (const action of ['associate', 'exclude']) {
        const r = runtime(); await loadedProject(r, 'A', project({}, [{target: 'api.example.test', source: 'agent', excluded: false}]));
        r.elements['project-network-targets'].value = 'draft.example.test';
        r.elements['project-network-asset'].value = 'api.example.test';
        const control = action === 'associate' ? r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '关联资产') : r.elements['project-network-bindings'].querySelector('button');
        const failed = control.click(); await flush();
        r.respond(1, {message: 'previous asset failure'}, false); await failed;
        const retry = control.click(); await flush(); r.respond(2, {}); await flush();
        r.respond(3, project({}, [{target: 'api.example.test', source: 'user', excluded: action === 'exclude'}])); await retry;
        assert.equal(r.elements['project-network-message'].textContent, '');
        assert.equal(r.elements['project-network-targets'].value, 'draft.example.test');
    }
});
test('failed project load clears and disables prior project controls', async () => {
    const r = runtime(); await loadedProject(r, 'A'); const load = r.api.loadProject('B'); r.respond(1, {error: 'project B denied'}, false); await load;
    assert.equal(r.elements['project-network-targets'].value, '');
    assert.equal(r.elements['project-network-mode'].disabled, true);
    assert.equal(r.elements['project-network-message'].textContent, 'project B denied');
});
test('language change preserves unsaved network inputs', async () => {
    const r = runtime(); await r.event('DOMContentLoaded'); await loadedProject(r, 'A');
    r.elements['project-network-targets'].value = 'unsaved.example.test'; await r.event('languagechange');
    assert.equal(r.elements['project-network-targets'].value, 'unsaved.example.test');
});


test('node filtering, editing credentials and deleting use the management API', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const node = {id: 'node-2', address: 'http://127.0.0.1:8082', enabled: true, eligible: true};
    const load = r.api.loadPool(); r.respond(0, {nodes: [{...node, id: 'node-1', address: 'http://127.0.0.1:8081'}, node]}); await load;
    r.elements['network-filter'].value = '8082'; await r.elements['network-filter'].fire('input');
    assert.equal(r.elements['network-rows'].children.length, 1);
    const buttons = () => r.elements['network-rows'].querySelectorAll('button');
    await buttons().find(e => e.textContent === '编辑').click();
    const edit = r.elements['network-edit-address']; edit.value = 'socks5://user:secret@127.0.0.1:1080';
    r.context.window.t = key => ({'network.edit': 'Edit', 'network.save': 'Save'}[key] || key);
    await r.event('languagechange'); assert.equal(edit.value, 'socks5://user:secret@127.0.0.1:1080'); assert.strictEqual(r.elements['network-edit-address'], edit);
    const saving = r.elements['network-edit-save'].click(); await flush();
    assert.equal(r.calls[1].options.method, 'PUT'); assert.equal(JSON.parse(r.calls[1].options.body).address, edit.value);
    r.respond(1, {}); await flush(); r.respond(2, {nodes: [node]}); await saving;
    const deleting = buttons().find(e => e.textContent === '删除').click(); await flush();
    assert.equal(r.calls[3].options.method, 'DELETE'); assert.equal(r.calls[3].url, '/api/network/proxies/node-2');
    r.respond(3, {}); await flush(); r.respond(4, {nodes: []}); await deleting;
});
test('stale binding errors cannot overwrite the next project status', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({}, [{target: 'api.example.test', source: 'agent', excluded: false}]));
    const click = r.elements['project-network-bindings'].querySelector('button').click(); await flush();
    await loadedProject(r, 'B'); const status = r.elements['project-network-message'].textContent;
    r.respond(1, {error: 'old project failure'}, false); await click;
    assert.equal(r.elements['project-network-message'].textContent, status);
});
test('save disables duplicate submissions and unrelated mode controls', async () => {
    const r = runtime(); await loadedProject(r, 'A');
    assert.equal(r.elements['project-network-config'].disabled, true); assert.equal(r.elements['project-network-proxy'].disabled, true);
    const button = r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '保存网络配置');
    const saving = button.click(); await flush(); await button.click(); assert.equal(r.calls.length, 2);
    assert.equal(r.elements['project-network-mode'].disabled, true);
    r.respond(1, {}); await flush(); r.respond(2, project()); await saving;
    assert.equal(r.elements['project-network-mode'].disabled, false);
});
test('scope-specific administrators cannot use global mutation controls', async () => {
    const r = runtime(); r.allow(true); r.context.authScope = 'own'; await r.event('DOMContentLoaded'); r.api.refreshPermissions();
    assert.equal(r.elements['network-import'].closest('[data-require-permission]').hidden, true);
});
test('all network copy keys have English and Chinese translations', () => {
    const zh = JSON.parse(fs.readFileSync(path.join(__dirname, '../static/i18n/zh-CN.json'), 'utf8')).network;
    const en = JSON.parse(fs.readFileSync(path.join(__dirname, '../static/i18n/en-US.json'), 'utf8')).network;
    assert.deepEqual(Object.keys(zh).sort(), Object.keys(en).sort());
    for (const key of Object.keys(zh)) { assert.ok(zh[key]); assert.ok(en[key]); }
});

test('text-only translated addresses stay readable without interpreting HTML', async () => {
    const r = runtime();
    r.context.window.t = (key, options = {}) => {
        if (key !== 'network.assigned') return key;
        const address = options.interpolation?.escapeValue === false ? options.address : options.address.replaceAll('/', '&#x2F;');
        return `指定节点：${address}`;
    };
    await loadedProject(r, 'A', {...project({mode: 'fixed_proxy'}), assigned_proxy: {address: 'socks5://127.0.0.1:1080'}});
    assert.match(r.elements['project-network-status'].textContent, /socks5:\/\/127\.0\.0\.1:1080/);
    assert.doesNotMatch(r.elements['project-network-status'].textContent, /&#x2F;/);
});

test('proxy policy status and controls do not imply an OpenVPN connection', async () => {
    const r = runtime(); await loadedProject(r, 'A', {...project({mode: 'fixed_proxy'}), assigned_proxy: {address: 'socks5://127.0.0.1:1080'}});
    assert.match(r.elements['project-network-status'].textContent, /项目代理已配置/);
    assert.doesNotMatch(r.elements['project-network-status'].textContent, /已断开/);
    const buttons = r.elements['project-network-card'].querySelectorAll('button');
    assert.equal(buttons.find(e => e.textContent === '连接 / 检查').disabled, true);
    assert.equal(buttons.find(e => e.textContent === '断开').disabled, true);
});

test('project network settings live inside the existing scrollable settings layout', async () => {
    const r = runtime();
    const column = r.context.document.createElement('div'); column.className = 'projects-settings-primary';
    r.elements['project-panel-settings'].append(column);
    await loadedProject(r, 'A');
    assert.strictEqual(r.elements['project-network-card'].parentNode, column);
});

test('status refresh preserves unsaved inputs and updates VPN and discovered assets', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({mode: 'fixed_vpn', vpn_profile_id: 'profile'}));
    r.elements['project-network-targets'].value = 'draft.example.test';
    r.elements['project-network-proxy'].value = 'socks5://user:secret@127.0.0.1:1080';
    const file = {name: 'draft.ovpn'}; r.elements['project-network-config'].files = [file];
    const refresh = r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '刷新状态').click(); await flush();
    assert.equal(r.elements['project-network-targets'].value, 'draft.example.test', 'refresh must not clear a draft while loading');
    r.respond(1, {...project({mode: 'fixed_vpn', vpn_profile_id: 'profile'}, [{target: 'api.example.test', source: 'agent'}]), vpn: {state: 'reconnecting'}}); await refresh;
    assert.equal(r.elements['project-network-targets'].value, 'draft.example.test');
    assert.equal(r.elements['project-network-proxy'].value, 'socks5://user:secret@127.0.0.1:1080');
    assert.strictEqual(r.elements['project-network-config'].files[0], file);
    assert.match(r.elements['project-network-status'].textContent, /重连中/);
    assert.match(r.elements['project-network-bindings'].children[0].children[0].textContent, /api.example.test/);
});

test('external certificates without a selected ovpn are rejected before any save', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({mode: 'fixed_vpn', vpn_profile_id: 'old'}));
    r.elements['project-network-certificates'].files = [{name: 'client.key', size: 10}];
    const saving = r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '保存网络配置').click(); await flush();
    assert.equal(r.calls.length, 1, 'do not silently ignore selected certificate files');
    await saving; assert.match(r.elements['project-network-message'].textContent, /\.ovpn/);
});

test('saved crawl configurations stay server-side and the dialog never lists them', async () => {
    const r = runtime(); r.allow(true); const opening = r.api.openPool();
    r.respond(0, {nodes: []}); await opening;
    assert.equal(r.elements['network-source-rows'], undefined);
    assert.equal(r.elements['network-source-configs'], undefined);
    assert.doesNotMatch(r.root.textContent, /token-secret/);
});

test('a running diagnosis exposes cancellation and stops polling after cancellation', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const timers = []; r.context.setTimeout = fn => {timers.push(fn); return timers.length;};
    r.elements['network-target'].value = 'https://example.test';
    const loading = r.api.loadPool(); r.respond(0, {nodes: [{id: 'n1', address: 'http://127.0.0.1:8081', enabled: true}]}); await loading;
    const diagnosing = r.elements['network-rows'].querySelectorAll('button').find(e => e.textContent === '验证').click(); await flush();
    r.respond(1, {job_id: 'job-1'}); await flush();
    assert.equal(r.elements['network-job-cancel'].hidden, false);
    const cancelling = r.elements['network-job-cancel'].click(); await flush();
    assert.equal(r.calls[3].url, '/api/network/jobs/job-1/cancel');
    r.respond(3, {ok: true}); await cancelling;
    r.respond(2, {state: 'failed', error: 'context canceled'}); await flush(); r.respond(4, {nodes: [{id: 'n1', address: 'http://127.0.0.1:8081', enabled: true}]}); await diagnosing;
    assert.match(r.elements['network-message'].textContent, /取消/);
    assert.equal(r.elements['network-job-cancel'].hidden, true);
    assert.equal(r.calls.length, 5);
    assert.equal(r.calls[4].url, '/api/network/proxies?target=https%3A%2F%2Fexample.test', 'refresh persisted results without polling the cancelled job again');
});

test('visible project polling updates status without replacing drafts and ignores switched projects', async () => {
    const r = runtime(); const timers = [];
    r.context.document.visibilityState = 'visible'; r.elements['project-panel-settings'].getClientRects = () => [1];
    r.context.setTimeout = fn => {timers.push(fn); return timers.length;}; r.context.clearTimeout = () => {};
    await loadedProject(r, 'A', project({mode: 'fixed_vpn', vpn_profile_id: 'a'}));
    r.elements['project-network-targets'].value = 'draft.example.test';
    const polling = timers.shift()(); await flush();
    r.respond(1, {...project({mode: 'fixed_vpn', vpn_profile_id: 'a'}), vpn: {state: 'ready'}}); await polling;
    assert.match(r.elements['project-network-status'].textContent, /已就绪/); assert.equal(r.elements['project-network-targets'].value, 'draft.example.test');
    const late = timers.shift()(); await flush(); await loadedProject(r, 'B', project({mode: 'fixed_proxy'}));
    r.respond(2, {...project({mode: 'fixed_vpn', vpn_profile_id: 'a'}), vpn: {state: 'failed'}}); await late;
    assert.match(r.elements['project-network-status'].textContent, /项目代理已配置/);
});

test('connecting serializes project mutations and refresh failures retain editable drafts', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({mode: 'fixed_vpn', vpn_profile_id: 'profile'}));
    const buttons = r.elements['project-network-card'].querySelectorAll('button');
    const connecting = buttons.find(e => e.textContent === '连接 / 检查').click(); await flush();
    await buttons.find(e => e.textContent === '断开').click(); assert.equal(r.calls.length, 2);
    r.respond(1, {error: 'VPN unavailable'}, false); await connecting;
    r.elements['project-network-targets'].value = 'draft.example.test';
    const refreshing = buttons.find(e => e.textContent === '刷新状态').click(); await flush();
    r.respond(2, {error: 'temporary read failure'}, false); await refreshing;
    assert.equal(r.elements['project-network-targets'].value, 'draft.example.test');
    assert.equal(r.elements['project-network-targets'].disabled, false);
    assert.equal(r.elements['project-network-message'].textContent, 'temporary read failure');
});

test('pending VPN connection can be cancelled and explicitly disconnected from the card', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({mode: 'fixed_vpn', vpn_profile_id: 'profile'}));
    const connecting = r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '连接 / 检查').click(); await flush();
    r.elements['project-network-job-cancel'].setAttribute('aria-disabled', 'true');
    r.respond(1, {job_id: 'vpn-job'}); await flush();
    const cancel = r.elements['project-network-job-cancel']; assert.ok(cancel); assert.equal(cancel.hidden, false); assert.equal(cancel.disabled, false);
    assert.equal(cancel.getAttribute('aria-disabled'), 'false', 'RBAC disabled state must clear when cancellation becomes available');
    const cancelling = cancel.click(); await flush();
    assert.equal(r.calls[3].url, '/api/network/jobs/vpn-job/cancel'); r.respond(3, {ok: true}); await flush();
    assert.equal(r.calls[4].url, '/api/projects/A/vpn/disconnect');
    r.respond(2, {state: 'failed', error: 'context canceled'}); await flush();
    assert.equal(r.elements['project-network-mode'].disabled, true, 'wait for disconnect cleanup before allowing a new connection');
    r.respond(4, {ok: true}); await flush();
    assert.equal(r.calls[5].url, '/api/projects/A/network-policy'); r.respond(5, project({mode: 'fixed_vpn', vpn_profile_id: 'profile'}));
    await cancelling; await connecting;
    assert.match(r.elements['project-network-message'].textContent, /取消 VPN/); assert.equal(cancel.hidden, true);
});

test('asset changes retain an unsubmitted VPN profile and target draft', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({}, [{target: 'api.example.test', source: 'agent'}]));
    r.elements['project-network-targets'].value = 'draft.example.test';
    r.elements['project-network-mode'].value = 'fixed_vpn';
    const file = {name: 'draft.ovpn'}; r.elements['project-network-config'].files = [file];
    const excluding = r.elements['project-network-bindings'].querySelector('button').click(); await flush();
    r.respond(1, {}); await flush(); r.respond(2, project({}, [{target: 'api.example.test', source: 'user', excluded: true}])); await excluding;
    assert.equal(r.elements['project-network-targets'].value, 'draft.example.test');
    assert.equal(r.elements['project-network-mode'].value, 'fixed_vpn');
    assert.strictEqual(r.elements['project-network-config'].files[0], file);
});

test('a pending VPN job in project A does not disable the same controls in project B', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({mode: 'fixed_vpn', vpn_profile_id: 'a'}));
    const connect = r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '连接 / 检查');
    const first = connect.click(); await flush(); r.respond(1, {job_id: 'job-a'}); await flush();
    await loadedProject(r, 'B', project({mode: 'fixed_vpn', vpn_profile_id: 'b'}));
    assert.equal(connect.disabled, false, 'project A must not block managing another VPN');
    const second = connect.click(); await flush(); assert.equal(r.calls[4].url, '/api/projects/B/vpn/connect');
    r.respond(2, {state: 'failed', error: 'old job failed'}); await first;
    assert.equal(connect.disabled, true, 'finishing A must not unlock the pending B operation');
    r.respond(4, {error: 'B connection unavailable'}, false); await second;
    assert.equal(r.elements['project-network-message'].textContent, 'B connection unavailable');
});

test('unchanged status polling preserves the asset button DOM and keyboard focus', async () => {
    const r = runtime(); const data = project({}, [{target: 'api.example.test', source: 'agent', revision: 1}]);
    await loadedProject(r, 'A', data); const original = r.elements['project-network-bindings'].children[0];
    const refresh = r.elements['project-network-card'].querySelectorAll('button').find(e => e.textContent === '刷新状态').click(); await flush();
    r.respond(1, data); await refresh;
    assert.strictEqual(r.elements['project-network-bindings'].children[0], original, 'do not rebuild focused or hovered asset controls every three seconds');
});

test('password VPN upload submits write-only credentials with the selected profile', async () => {
    const r = runtime(); await loadedProject(r, 'A', project({mode: 'fixed_vpn'}));
    const username=r.elements['project-network-username'], password=r.elements['project-network-password']; assert.ok(username); assert.ok(password);
    username.value='fixture-account'; password.value='synthetic-secret';
    r.elements['project-network-config'].files=[{name:'client.ovpn',size:64,text:async()=>'client\nauth-user-pass\n'}];
    const save=r.elements['project-network-card'].querySelectorAll('button').find(e=>e.textContent==='保存网络配置').click(); await flush();
    const body=JSON.parse(r.calls[1].options.body);
    assert.equal(r.calls[1].url,'/api/projects/A/vpn-profile'); assert.equal(body.credentials.username,'fixture-account'); assert.equal(body.credentials.password,'synthetic-secret');
    r.respond(1,{}); await flush(); r.respond(2,{...project({mode:'fixed_vpn',vpn_profile_id:'new'}),vpn_has_auth:true}); await save;
    assert.equal(username.value,''); assert.equal(password.value,''); assert.match(r.elements['project-network-auth-hint'].textContent,/已配置/);
});

test('password-only rotation reuses the stored profile and rejects incomplete pairs', async () => {
    const r=runtime(); await loadedProject(r,'A',{...project({mode:'fixed_vpn',vpn_profile_id:'stored'}),vpn_has_auth:true});
    const username=r.elements['project-network-username'], password=r.elements['project-network-password']; assert.ok(username); assert.ok(password);
    assert.equal(password.value,''); username.value='fixture-account';
    const button=r.elements['project-network-card'].querySelectorAll('button').find(e=>e.textContent==='保存网络配置');
    await button.click(); assert.equal(r.calls.length,1); assert.match(r.elements['project-network-message'].textContent,/同时填写/);
    password.value='synthetic-rotated'; const saving=button.click(); await flush();
    assert.equal(r.calls[1].url,'/api/projects/A/vpn-profile'); const body=JSON.parse(r.calls[1].options.body);
    assert.equal(body.config,''); assert.equal(body.credentials.password,'synthetic-rotated');
    r.respond(1,{}); await flush(); r.respond(2,{...project({mode:'fixed_vpn',vpn_profile_id:'rotated'}),vpn_has_auth:true}); await saving;
    await loadedProject(r,'B',project({mode:'auto'})); assert.equal(username.value,''); assert.equal(password.value,''); assert.equal(password.disabled,true);
});

test('changing projects during password profile reading cannot send previous project secrets', async () => {
    const r=runtime(); await loadedProject(r,'A',project({mode:'fixed_vpn'}));
    assert.ok(r.elements['project-network-password']); r.elements['project-network-username'].value='fixture-a'; r.elements['project-network-password'].value='synthetic-a';
    let finish; r.elements['project-network-config'].files=[{name:'client.ovpn',size:64,text:()=>new Promise(resolve=>{finish=resolve;})}];
    const saving=r.elements['project-network-card'].querySelectorAll('button').find(e=>e.textContent==='保存网络配置').click(); await flush();
    await loadedProject(r,'B',project({mode:'fixed_vpn'})); finish('client\nauth-user-pass\n'); await saving;
    assert.equal(r.calls.filter(c=>c.options?.method==='POST').length,0); assert.equal(r.elements['project-network-password'].value,'');
});

test('subscription dialog imports pasted content and reports unsupported protocols', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    await r.elements['network-open-subscription'].click();
    assert.equal(r.elements['network-subscription-dialog'].open, true);
    r.elements['network-subscription-input'].value = 'socks5://user:password@127.0.0.1:1080';
    assert.equal(r.elements['network-subscription-authorized'], undefined);
    const saving = r.elements['network-subscription-submit'].click(); await flush();
    assert.equal(r.calls[0].url, '/api/network/subscriptions/import');
    const payload = JSON.parse(r.calls[0].options.body);
    assert.equal(payload.authorized, undefined); assert.match(payload.content, /socks5:/);
    r.respond(0, {job_id: 'import-1'}); await flush();
    r.respond(1, {state: 'completed', result: {imported: 1, skipped: 2, unsupported: {vmess: 2}}}); await flush();
    r.respond(2, {nodes: []}); await saving;
    assert.match(r.elements['network-subscription-dialog-message'].textContent, /vmess.*2/);
    assert.equal(r.elements['network-subscription-input'].value, '');
});

test('validation dialog saves matching and cleanup settings without starting work for save only', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const opening = r.elements['network-open-validation'].click(); await flush();
    assert.equal(r.calls[0].url, '/api/network/validation');
    r.respond(0, {target: 'https://example.test', contains: '', failure_action: 'keep', failure_threshold: 3}); await opening;
    r.elements['network-validation-contains'].value = 'expected';
    r.elements['network-validation-action'].value = 'disable';
    const saving = r.elements['network-validation-save'].click(); await flush();
    const payload = JSON.parse(r.calls[1].options.body);
    assert.equal(payload.contains, 'expected'); assert.equal(payload.failure_action, 'disable');
    r.respond(1, payload); await flush();
    assert.equal(r.calls[2].url.startsWith('/api/network/proxies'), true);
    r.respond(2, {nodes: []}); await saving;
    assert.equal(r.calls.length, 3); assert.equal(r.calls[1].options.method, 'PUT');
    assert.equal(r.calls.some(call => call.url === '/api/network/validate'), false);
});

test('validation configuration preserves the diagnostic target and its observations', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    r.elements['network-target'].value = 'https://a.example.test';
    const loading = r.api.loadPool();
    const observation = {node_id: 'node-a', target: 'https://a.example.test:443', reachable: true, http_status: 204, latency_ms: 1};
    r.respond(0, {candidates: [{node: {id: 'node-a', address: 'http://127.0.0.1:8080', enabled: true}, observation}]}); await loading;
    const opening = r.elements['network-open-validation'].click(); await flush();
    r.respond(1, {target: 'https://www.baidu.com', failure_action: 'keep', failure_threshold: 3}); await opening;
    assert.equal(r.elements['network-target'].value, 'https://a.example.test');
    r.elements['network-validation-target'].value = 'https://validation.example.test';
    const saving = r.elements['network-validation-save'].click(); await flush();
    r.respond(2, {}); await flush();
    r.respond(3, {candidates: [{node: {id: 'node-a', address: 'http://127.0.0.1:8080', enabled: true}, observation}], pool_observations: {}}); await saving;
    assert.equal(r.elements['network-target'].value, 'https://a.example.test');
    const shown = JSON.parse(r.elements['network-rows'].querySelector('[data-network-observation]').getAttribute('data-network-observation'));
    assert.deepEqual(shown, observation);
});

test('saving changed validation settings discards health from the previous check', async () => {
    for (const field of ['target', 'contains']) {
        const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
        const nodes = [{id: 'old-pass', address: 'http://127.0.0.1:8080', enabled: true}];
        const loading = r.api.loadPool();
        r.respond(0, {nodes, pool_observations: {'old-pass': {reachable: true, http_status: 200, latency_ms: 5}}}); await loading;
        assert.match(r.elements['network-rows'].children[0].children.map(domText).join(), /200/);
        const opening = r.elements['network-open-validation'].click(); await flush();
        r.respond(1, {target: 'https://www.baidu.com', contains: '', failure_action: 'keep', failure_threshold: 3}); await opening;
        r.elements['network-validation-' + field].value = field === 'target' ? 'https://validation.example.test' : 'new marker';
        const saving = r.elements['network-validation-save'].click(); await flush();
        r.respond(2, {}); await flush();
        assert.equal(r.calls[3]?.url.startsWith('/api/network/proxies'), true, field + ' must reconcile cleared validation results');
        r.respond(3, {nodes, pool_observations: {}}); await saving;
        assert.doesNotMatch(r.elements['network-rows'].children[0].children.map(domText).join(), /200/);
        assert.equal(r.calls.some(call => call.url === '/api/network/validate'), false);
    }
});

test('saving validation invalidates old health even when its refresh fails or becomes stale', async () => {
    for (const scenario of ['failure', 'target-change']) {
        const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
        const nodes = [{id: 'old-pass', address: 'http://127.0.0.1:8080', enabled: true}];
        const loading = r.api.loadPool();
        r.respond(0, {nodes, pool_observations: {'old-pass': {reachable: true, http_status: 200}}}); await loading;
        const opening = r.elements['network-open-validation'].click(); await flush();
        r.respond(1, {target: 'https://www.baidu.com', failure_action: 'keep', failure_threshold: 3}); await opening;
        r.elements['network-validation-contains'].value = 'new marker';
        const saving = r.elements['network-validation-save'].click(); await flush();
        r.respond(2, {}); await flush();
        if (scenario === 'target-change') {
            r.elements['network-target'].value = 'https://diagnostic.example.test';
            await r.elements['network-target'].fire('input');
        }
        r.respond(3, scenario === 'failure' ? {message: 'synthetic refresh failure'} : {nodes, pool_observations: {}}, scenario !== 'failure'); await saving;
        assert.doesNotMatch(r.elements['network-rows'].children[0].children.map(domText).join(), /200/, scenario);
        if (scenario === 'failure') assert.match(r.elements['network-message'].textContent, /synthetic refresh failure/);
    }
});

test('source save and collect reuses system keys and never sends per-source credentials', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    r.elements['network-source-name'].value = 'Fixture'; r.elements['network-source-kind'].value = 'hunter';
    r.elements['network-source-query'].value = 'fixture';
    assert.equal(r.elements['network-source-key'], undefined);
    assert.equal(r.elements['network-source-endpoint'], undefined);
    const saving = r.elements['network-source-crawl'].click(); await flush();
    const payload = JSON.parse(r.calls[0].options.body);
    assert.equal(payload.api_key, undefined); assert.equal(payload.api_url, undefined); assert.equal(payload.authorized, undefined);
    r.respond(0, {id: 'source-1'}); await flush();
    assert.equal(r.calls[1].url, '/api/network/sources/source-1/sync');
    r.respond(1, {job_id: 'source-job'}); await flush();
    r.respond(2, {state: 'completed', result: {imported: 2, skipped: 0}}); await flush();
    r.respond(3, {nodes: []}); await saving;
});

test('bulk management sends only selected nodes and preserves per-node validation display', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool();
    r.respond(0, {nodes: [{id: 'one', address: 'http://127.0.0.1:8001', eligible: true, enabled: true}, {id: 'two', address: 'http://127.0.0.1:8002', eligible: true, enabled: true}], pool_observations: {one: {reachable: true, latency_ms: 5, http_status: 200}}}); await loading;
    assert.match(r.elements['network-rows'].children[0].textContent + r.elements['network-rows'].children[0].children.map(domText).join(), /200/);
    r.elements['network-select-one'].checked = true; await r.elements['network-select-one'].fire('change');
    r.elements['network-bulk-action'].value = 'disable';
    const applying = r.elements['network-bulk-apply'].click(); await flush();
    assert.deepEqual(JSON.parse(r.calls[1].options.body), {node_ids: ['one'], action: 'disable'});
    r.respond(1, {updated: 1, skipped: 0}); await flush(); r.respond(2, {nodes: []}); await applying;
});

test('an enabled node with failed validation is not labeled as reachable or available', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool();
    r.respond(0, {nodes: [{id: 'failed', address: 'http://127.0.0.1:8080', enabled: true}], pool_observations: {failed: {reachable: false, http_status: 407, latency_ms: 1}}}); await loading;
    const row = r.elements['network-rows'].children[0];
    assert.equal(row.children[4].children[0].textContent, '已启用');
    assert.match(domText(row.children[6]), /失败 407/);
});

test('validation load disables submission and ignores an older response after reopening', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const first = r.elements['network-open-validation'].click(); await flush();
    assert.equal(r.elements['network-validation-save'].disabled, true);
    assert.equal(r.elements['network-validation-save-run'].disabled, true);
    await r.elements['network-validation-save'].click(); assert.equal(r.calls.length, 1);
    r.respond(0, {target: 'https://old.test', failure_action: 'keep', failure_threshold: 3}); await first;
    const second = r.elements['network-open-validation'].click(); await flush();
    assert.equal(r.elements['network-validation-target'].disabled, true);
    r.respond(1, {target: 'https://current.test', failure_action: 'keep', failure_threshold: 3}); await second;
    assert.equal(r.elements['network-validation-target'].value, 'https://current.test');
    assert.equal(r.elements['network-validation-save'].disabled, false);
});

test('a partially failed subscription import refreshes the pool and reports persisted progress', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded'); await r.elements['network-open-subscription'].click();
    r.elements['network-subscription-input'].value = 'https://fixture.test/subscription'; r.elements['network-subscription-kind'].value = 'urls';
    const importing = r.elements['network-subscription-submit'].click(); await flush(); r.respond(0, {job_id: 'partial'}); await flush();
    r.respond(1, {state: 'failed', error: 'second source failed', result: {imported: 10, skipped: 2}}); await flush();
    assert.equal(r.calls[2].url, '/api/network/proxies'); r.respond(2, {nodes: []}); await importing;
    assert.match(r.elements['network-subscription-dialog-message'].textContent, /10/);
    assert.match(r.elements['network-subscription-dialog-message'].textContent, /second source failed/);
    assert.equal(r.elements['network-subscription-input'].value, 'https://fixture.test/subscription');
});

test('opening collection keeps the crawl form clean regardless of saved sources', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const opening = r.elements['network-open-sources'].click(); await flush();
    r.respond(0, {sources: [{id: 'stored', name: 'hidden source'}], providers: [{kind: 'fofa', configured: true}]}); await opening;
    assert.equal(r.elements['network-source-dialog'].open, true);
    assert.equal(r.elements['network-source-rows'], undefined);
    assert.match(r.elements['network-source-query'].value, /protocol="socks5"/);
});

test('large pools render bounded pages and select only visible nodes', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading=r.api.loadPool();r.respond(0,{nodes:Array.from({length:45},(_,n)=>({id:'node-'+String(n).padStart(3,'0'),address:'http://127.0.0.1:'+(8000+n),enabled:true,eligible:true}))});await loading;
    assert.equal(r.elements['network-rows'].children.length,20);
    await r.elements['network-page-next'].click();assert.equal(r.elements['network-rows'].children.length,20);
    assert.equal(r.elements['network-rows'].children[0].children[1].textContent,'http://127.0.0.1:8020');
    await r.elements['network-page-next'].click();assert.equal(r.elements['network-rows'].children.length,5);assert.equal(r.elements['network-page-next'].disabled,true);
    r.elements['network-filter'].value='8044';await r.elements['network-filter'].fire('input');assert.equal(r.elements['network-rows'].children.length,1);assert.equal(r.elements['network-page-previous'].disabled,true);
});

test('collection starts with a usable FOFA query and screenshot collection limit', async () => {
    const r=runtime();await r.event('DOMContentLoaded');
    assert.equal(r.elements['network-source-query'].value,'protocol="socks5" && country="CN" && banner="Method:No Authentication"');
    assert.equal(r.elements['network-source-limit'].value,'5000');
    assert.ok(r.elements['network-source-name'].value);
});

test('query presets follow protocol and engine while preserving custom engine drafts', async () => {
    const r=runtime();r.allow(true);await r.event('DOMContentLoaded');
    const query=r.elements['network-source-query'],kind=r.elements['network-source-kind'];
    query.value='protocol="socks5" && ip="192.0.2.10"';await query.fire('input');
    kind.value='quake';await kind.fire('change');assert.equal(query.value,'service:socks5 AND country: "CN" AND response:"No authentication"');
    kind.value='fofa';await kind.fire('change');assert.equal(query.value,'protocol="socks5" && ip="192.0.2.10"');
    r.elements['network-source-protocol'].value='http';await r.elements['network-source-protocol'].fire('change');
    assert.equal(query.value,'protocol="http" && country="CN"');
    r.elements['network-source-country'].value='';await r.elements['network-source-country'].fire('change');
    assert.equal(query.value,'protocol="http"');
    kind.value='hunter';await kind.fire('change');assert.equal(query.value,'protocol="http"');
});

test('refresh and language changes preserve edited queries and explicit reset needs confirmation', async () => {
    const r=runtime();r.allow(true);await r.event('DOMContentLoaded');
    const query=r.elements['network-source-query'];query.value='ip="192.0.2.10"';
    await r.event('languagechange');assert.equal(query.value,'ip="192.0.2.10"');
    r.context.window.confirm=()=>false;await r.elements['network-source-query-reset'].click();assert.equal(query.value,'ip="192.0.2.10"');
    r.context.window.confirm=()=>true;await r.elements['network-source-query-reset'].click();assert.match(query.value,/protocol="socks5"/);
});

test('engine switching keeps per-engine query drafts and invalid template input never changes a query', async () => {
    const r=runtime();r.allow(true);await r.event('DOMContentLoaded');
    assert.equal(r.elements['network-source-key'],undefined);assert.equal(r.elements['network-source-endpoint'],undefined);
    const kind=r.elements['network-source-kind'];
    const query=r.elements['network-source-query'];
    kind.value='quake';await kind.fire('change');
    const quakeDraft=query.value;assert.match(quakeDraft,/service:/);
    kind.value='fofa';await kind.fire('change');assert.notEqual(query.value,quakeDraft);
    kind.value='quake';await kind.fire('change');assert.equal(query.value,quakeDraft);
    kind.value='fofa';await kind.fire('change');
    const original=query.value;
    r.elements['network-source-country'].value='C"';await r.elements['network-source-country'].fire('change');
    assert.equal(query.value,original);assert.match(r.elements['network-message'].textContent,/两个英文字母/);
    r.elements['network-source-country'].value='CN';r.elements['network-source-no-auth'].checked=false;await r.elements['network-source-no-auth'].fire('change');
    assert.equal(query.value,'protocol="socks5" && country="CN"');
});

test('crawler exposes one clear main action and no source selection controls', async () => {
    const r=runtime();r.allow(true);const opening=r.api.openPool();r.respond(0,{nodes:[]});await opening;
    const panel=r.elements['network-source-dialog'];
    assert.ok(r.elements['network-source-crawl']);
    assert.equal(r.elements['network-source-actions'].querySelectorAll('button').filter(b=>!b.hidden).map(b=>b.textContent).join(','),'爬取');
    assert.equal(panel.querySelectorAll('button').some(b=>['保存来源','保存并采集','采集全部来源','采集选中来源'].includes(b.textContent)),false);
    assert.equal(r.elements['network-source-rows'], undefined);
    assert.equal(r.elements['network-source-configs'], undefined);
});

test('crawl retains its configuration and reuses the saved id for the next run', async () => {
    const r=runtime();r.allow(true);await r.event('DOMContentLoaded');
    const query=r.elements['network-source-query'].value;
    const first=r.elements['network-source-crawl'].click();await flush();
    assert.equal(r.elements['network-source-kind'].disabled,true);
    r.respond(0,{id:'same-config'});await flush();r.respond(1,{job_id:'crawl-one'});await flush();r.respond(2,{state:'completed',result:{imported:2,skipped:0}});await flush();r.respond(3,{nodes:[]});await first;
    assert.equal(r.elements['network-source-query'].value,query);assert.equal(r.elements['network-source-kind'].disabled,false);
    const second=r.elements['network-source-crawl'].click();await flush();assert.equal(JSON.parse(r.calls[4].options.body).id,'same-config');
    r.respond(4,{message:'fixture stopped'},false);await second;
});

test('complete proxy export is an admin download named proxies.txt', async () => {
    const r=runtime();await r.event('DOMContentLoaded');
    const exportButton=r.elements['page-network'].querySelectorAll('button').find(b=>b.textContent==='导出代理');
    assert.ok(exportButton);assert.equal(exportButton.hidden,true);r.allow(true);r.api.refreshPermissions();assert.equal(exportButton.hidden,false);
    const create=r.context.document.createElement;let link;
    r.context.document.createElement=tag=>{const e=create(tag);if(tag==='a')link=e;return e;};r.context.URL={createObjectURL:()=> 'blob:synthetic-export',revokeObjectURL:()=>{}};
    const downloading=exportButton.click();await flush();assert.equal(r.calls[0].url,'/api/network/export');
    r.pending[0]({ok:true,blob:async()=>new Blob(['http://fixture:synthetic-pass@127.0.0.1:1080'])});await downloading;assert.equal(link.download,'proxies.txt');
});


test('failed node edits retain credentials draft and keep the dialog open', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool(); r.respond(0, {nodes: [{id: 'one', address: 'http://192.0.2.1:8080', enabled: true}]}); await loading;
    await r.elements['network-rows'].querySelectorAll('button').find(b => b.textContent === '编辑').click();
    const input = r.elements['network-edit-address']; input.value = 'socks5://fixture:synthetic-secret@192.0.2.1:1080';
    const saving = r.elements['network-edit-save'].click(); await flush(); r.respond(1, {message: 'save rejected'}, false); await saving;
    assert.equal(r.elements['network-edit-dialog'].open, true); assert.match(input.value, /synthetic-secret/);
    assert.match(r.elements['network-edit-dialog-message'].textContent, /save rejected/);
});

test('a late edit response cannot close or clear a different node draft', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const nodes = ['one', 'two'].map(id => ({id, address: 'http://' + id + '.example.test:8080', enabled: true}));
    const loading = r.api.loadPool(); r.respond(0, {nodes}); await loading;
    const rows = r.elements['network-rows'].children;
    await rows[0].querySelectorAll('button').find(b => b.textContent === '编辑').click();
    r.elements['network-edit-address'].value = 'http://192.0.2.1:8080';
    const saving = r.elements['network-edit-save'].click(); await flush();
    await rows[1].querySelectorAll('button').find(b => b.textContent === '编辑').click();
    r.elements['network-edit-address'].value = 'http://192.0.2.2:8080';
    r.respond(1, {}); await flush(); r.respond(2, {nodes}); await saving;
    assert.equal(r.elements['network-edit-dialog'].open, true); assert.equal(r.elements['network-edit-address'].value, 'http://192.0.2.2:8080');
});


test('validation results open full selectable details for target and pool checks', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const reason = 'Head "https://target.example.test:443": context deadline exceeded <literal>';
    const loading = r.api.loadPool(); r.respond(0, {candidates: [{node: {id: 'one', address: 'socks5://192.0.2.1:1080', enabled: true}, observation: {target: 'https://target.example.test:443', reachable: false, latency_ms: 5001, reason, stage: 'target_unreachable', observed_at: '2026-10-22T10:00:00Z'}}], pool_observations: {one: {target: 'https://pool.example.test:443', reachable: false, latency_ms: 5000, reason: 'pool timeout', stage: 'connect'}}}); await loading;
    const row = r.elements['network-rows'].children[0];
    const trigger = row.children[5].querySelector('button'); assert.ok(trigger, 'observations must be keyboard-accessible buttons');
    await trigger.click();
    assert.equal(r.elements['network-observation-dialog'].open, true);
    const details = r.elements['network-observation-details']; assert.equal(details.readOnly, true);
    assert.match(details.value, /192\.0\.2\.1:1080/); assert.ok(details.value.includes(reason)); assert.match(details.value, /5001/); assert.match(details.value, /2026-10-22T10:00:00Z/);
    assert.equal(r.elements['network-observation-dialog'].querySelector('literal'), null);
    await row.children[6].querySelector('button').click();
    assert.match(details.value, /pool.example.test/); assert.match(details.value, /pool timeout/); assert.doesNotMatch(details.value, /target.example.test/);
});

test('details copy uses the full text and falls back to manual selection when clipboard is unavailable', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool(); r.respond(0, {nodes: [{id: 'one', address: 'http://192.0.2.1:8080', enabled: true}], pool_observations: {one: {reachable: false, reason: 'full failure reason', latency_ms: 5000}}}); await loading;
    await r.elements['network-rows'].children[0].children[6].querySelector('button').click();
    let copied; r.context.navigator = {clipboard: {writeText: async text => {copied = text;}}};
    await r.elements['network-observation-copy'].click(); assert.equal(copied, r.elements['network-observation-details'].value);
    r.context.navigator.clipboard.writeText = async () => {throw Error('denied');};
    const details = r.elements['network-observation-details']; let selected = false; details.focus = () => {}; details.select = () => {selected = true;};
    r.context.document.execCommand = () => false;
    await r.elements['network-observation-copy'].click(); assert.equal(selected, true); assert.match(r.elements['network-observation-dialog-message'].textContent, /Ctrl\+C|手动/);
    assert.equal(r.elements['network-observation-dialog'].open, true);
});

test('authenticated read-only users can inspect results and the footer exposes complete messages', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const loading = r.api.loadPool(); r.respond(0, {nodes: [{id: 'one', address: 'http://192.0.2.1:8080', enabled: true}], pool_observations: {one: {reachable: false, reason: 'readable failure', latency_ms: 5000}}}); await loading;
    r.context.window.hasPermission = () => false;
    await r.elements['network-rows'].children[0].children[6].querySelector('button').click(); r.api.refreshPermissions();
    assert.equal(r.elements['network-observation-dialog'].open, true);
    const footer = r.elements['network-message']; assert.equal(footer.tagName, 'BUTTON'); footer.textContent = 'Full aggregate result with a long error reason'; await footer.click();
    assert.equal(r.elements['network-observation-details'].value, footer.textContent);
});


test('proxy display order stays fixed when validation changes backend candidate ranking', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded'); r.elements['network-target'].value = 'https://target.example.test';
    const a = {id: 'a', address: 'http://192.0.2.1:8080', enabled: true}, b = {id: 'b', address: 'http://192.0.2.2:8080', enabled: true};
    const loading = r.api.loadPool(); r.respond(0, {candidates: [{node: b, observation: {reachable: true, http_status: 200, latency_ms: 1}}, {node: a}]}); await loading;
    const addresses = () => r.elements['network-rows'].children.map(row => row.children[1].textContent);
    assert.deepEqual(addresses(), [a.address, b.address]);
    r.elements['network-select-a'].checked = true; await r.elements['network-select-a'].fire('change');
    const refresh = r.api.loadPool(); r.respond(1, {candidates: [{node: a, observation: {reachable: true, http_status: 200, latency_ms: 2}}, {node: b, observation: {reachable: false, latency_ms: 5000, reason: 'timeout'}}]}); await refresh;
    assert.deepEqual(addresses(), [a.address, b.address]); assert.equal(r.elements['network-select-a'].checked, true);
    assert.match(domText(r.elements['network-rows'].children[1].children[5]), /timeout/);
});

test('validation refresh preserves the current page and selected rows in a large pool', async () => {
    const r = runtime(); r.allow(true); await r.event('DOMContentLoaded');
    const nodes = Array.from({length: 45}, (_, i) => ({id: 'n' + String(i).padStart(3, '0'), address: 'http://127.0.0.1:' + (8000 + i), enabled: true}));
    const loading = r.api.loadPool(); r.respond(0, {candidates: [...nodes].reverse().map(node => ({node}))}); await loading;
    await r.elements['network-page-next'].click();
    const visible = () => r.elements['network-rows'].children.map(row => row.children[1].textContent);
    const before = visible(); assert.equal(before[0], nodes[20].address);
    r.elements['network-select-n025'].checked = true; await r.elements['network-select-n025'].fire('change');
    const refresh = r.api.loadPool(); r.respond(1, {candidates: [nodes[25], ...nodes.filter(n => n.id !== 'n025')].map(node => ({node, observation: {reachable: node.id === 'n025', latency_ms: 1}}))}); await refresh;
    assert.deepEqual(visible(), before); assert.equal(r.elements['network-select-n025'].checked, true); assert.match(r.elements['network-page-summary'].textContent, /2 \/ 3/);
});

test('project network modes show only the relevant proxy or VPN fields', async()=>{
 const r=runtime();r.allow(true);await loadedProject(r,'A',project());
 const mode=r.elements['project-network-mode'];
 assert.equal(r.elements['project-network-proxy'].closest('.network-field').hidden,true);
 assert.equal(r.elements['project-network-config'].closest('.network-field').hidden,true);
 mode.value='fixed_proxy';await mode.fire('change');
 assert.equal(r.elements['project-network-proxy'].closest('.network-field').hidden,false);
 assert.equal(r.elements['project-network-config'].closest('.network-field').hidden,true);
 mode.value='fixed_vpn';await mode.fire('change');
 assert.equal(r.elements['project-network-proxy'].closest('.network-field').hidden,true);
 assert.equal(r.elements['project-network-config'].closest('.network-field').hidden,false);
 assert.equal(r.elements['project-network-dns'].closest('.network-field').hidden,false);
});
test('network draft detection tracks mode and credentials without changing on status refresh',async()=>{
 const r=runtime();r.allow(true);await loadedProject(r,'A',project());assert.equal(r.api.hasProjectDraft(),false);
 r.elements['project-network-mode'].value='fixed_vpn';await r.elements['project-network-mode'].fire('change');assert.equal(r.api.hasProjectDraft(),true);
 r.elements['project-network-mode'].value='auto';await r.elements['project-network-mode'].fire('change');assert.equal(r.api.hasProjectDraft(),false);
 r.elements['project-network-password'].value='synthetic-only';assert.equal(r.api.hasProjectDraft(),true);
});

test('a committed network save with a failed follow-up read explains recovery and can refresh',async()=>{
 const r=runtime();r.allow(true);await loadedProject(r,'A',project());r.elements['project-network-targets'].value='new.example.test';
 const saving=r.elements['project-network-card'].querySelectorAll('button').find(e=>e.textContent==='\u4fdd\u5b58\u7f51\u7edc\u914d\u7f6e').click();await flush();r.respond(1,{policy:{mode:'auto',version:2,targets:['new.example.test']}});await flush();r.respond(2,{error:'Synthetic read failure'},false);await saving;
 assert.match(r.elements['project-network-message'].textContent,/\u5df2\u4fdd\u5b58/);assert.equal(r.elements['project-network-mode'].disabled,true);
 const retry=r.elements['project-network-card'].querySelectorAll('button').find(e=>e.textContent==='\u5237\u65b0\u72b6\u6001').click();await flush();r.respond(3,project({version:2,targets:['new.example.test']}));await retry;assert.equal(r.elements['project-network-targets'].value,'new.example.test');assert.equal(r.elements['project-network-mode'].disabled,false);
});
