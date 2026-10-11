const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const source = fs.readFileSync('web/static/js/projects.js', 'utf8');
function harness(facts, selection, ok = true) {
    const opened = [], requests = [], messages = [];
    const c = vm.createContext({ currentProjectId: 'project1', URLSearchParams, apiFetch: async url => { requests.push(url); return { ok, json: async () => facts }; }, alert: message => messages.push(message), tp: key => key, prompt: () => selection, viewProjectFactBody: async key => opened.push(key), switchProjectTab: () => { throw Error('unexpected navigation'); }, loadProjectFacts: () => { throw Error('unexpected list refresh'); }, document: { getElementById: () => { throw Error('unexpected filter reset'); } } });
    vm.runInContext(source.slice(source.indexOf('async function viewFactsForVulnerability('), source.indexOf('function openProjectsOverlay(')), c);
    return { c, opened, requests, messages };
}
test('single related fact opens its detail without changing the page or filters', async () => {
    const h = harness([{ fact_key: 'evidence' }]);
    await h.c.viewFactsForVulnerability('v1');
    assert.deepEqual(h.opened, ['evidence']);
    assert.match(h.requests[0], /related_vulnerability_id=v1/);
});
test('no related facts shows a message without opening an empty modal or navigating', async () => {
    const h = harness([]);
    await h.c.viewFactsForVulnerability('v1');
    assert.equal(h.opened.length, 0);
    assert.deepEqual(h.messages, ['projects.noFactsForVulnerability']);
});
test('multiple facts open the selected detail and cancellation leaves the page intact', async () => {
    for (const selection of ['2', null, '', '9']) {
        const h = harness([{ fact_key: 'one' }, { fact_key: 'two' }], selection);
        await h.c.viewFactsForVulnerability('v1');
        assert.deepEqual(h.opened, selection === '2' ? ['two'] : []);
    }
});
test('failed related fact request reports the failure without opening a modal', async () => {
    const h = harness([], null, false);
    await h.c.viewFactsForVulnerability('v1');
    assert.deepEqual(h.messages, ['projects.loadRelatedFactsFailed']);
    assert.equal(h.opened.length, 0);
});
