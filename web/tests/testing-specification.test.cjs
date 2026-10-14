const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../static/js/testing-specification.js'), 'utf8');

function runtime() {
    const elements = {};
    const context = { window: {}, document: { addEventListener() {}, getElementById: id => elements[id] || null, createElement: () => ({setAttribute(key, value) { this[key] = value; }}) }, TextEncoder, TextDecoder, Map, console };
    vm.runInNewContext(source, context);
    return { api: context.window.TestingSpecifications, elements, window: context.window };
}

test('batch editor ignores out-of-order responses and responses from a closed dialog', async () => {
    const { api, elements, window } = runtime();
    for (const id of ['task-spec-mode', 'task-spec-name', 'task-spec-content', 'task-spec-file', 'task-spec-file-trigger', 'task-spec-save', 'task-spec-info', 'task-spec-hash', 'task-spec-task', 'batch-spec-mode', 'batch-spec-content']) {
        elements[id] = {value: '', setAttribute() {}};
    }
    elements['batch-spec-mode'].value = 'inherit';
    elements['batch-tasks-input'] = {value: 'Task A\nTask B'};
    elements['batch-queue-project-id'] = {value: 'synthetic-project'};
    elements['testing-specification-dialog'] = {open: false, showModal() {this.open = true;}};
    const select = elements['task-spec-task'];
    select.replaceChildren = () => { select.value = '0'; };
    const pending = [];
    window.apiFetch = () => new Promise(resolve => pending.push(spec => resolve({ok: true, json: async () => ({testing_specification: {content: spec}})})));
    window.alert = message => assert.fail(message);
    const first = api.openBatchTask();
    select.value = '1';
    const second = select.onchange();
    pending[1]('B rules');
    await second;
    elements['task-spec-mode'].value = 'override';
    elements['task-spec-content'].value = 'B edited rules';
    pending[0]('A rules');
    await first;
    assert.equal(elements['task-spec-content'].value, 'B edited rules');
    assert.equal(elements['task-spec-mode'].value, 'override');
    const closed = select.onchange();
    elements['testing-specification-dialog'].open = false;
    pending[2]('late rules');
    await closed;
    assert.equal(elements['task-spec-content'].value, 'B edited rules');
});

test('opening batch creation refreshes inherited rules after selecting the active project', async () => {
    const tasksSource = fs.readFileSync(path.join(__dirname, '../static/js/tasks.js'), 'utf8');
    const start = tasksSource.indexOf('async function showBatchImportModal()');
    const end = tasksSource.indexOf('\n// 关闭新建任务模态框', start);
    const events = [];
    const projectSelect = {value: '', dispatchEvent(event) { events.push([event.type, this.value]); }};
    const elements = {'batch-import-modal': {}, 'batch-tasks-input': {value: ''}, 'batch-queue-project-id': projectSelect};
    const context = vm.createContext({
        window: {TestingSpecifications: {resetBatch() {}}},
        document: {getElementById: id => elements[id] || null}, Event,
        handleBatchScheduleModeChange() {}, updateBatchImportStats() {},
        async refreshBatchProjectSelectOptions() {projectSelect.value = 'synthetic-project';},
        refreshBatchFormSelects() {}, openAppModal() {},
    });
    vm.runInContext(tasksSource.slice(start, end), context);
    await context.showBatchImportModal();
    assert.deepEqual(events, [['change', 'synthetic-project']]);
});

test('imports only UTF-8 text specifications and rejects oversized/binary content', async () => {
    const { api } = runtime();
    const file = (name, bytes) => ({ name, size: bytes.length, arrayBuffer: async () => Uint8Array.from(bytes).buffer });
    const imported = await api.parseFile(file('rules.md', Buffer.from('范围\r\nOnly app.example.test')));
    assert.equal(imported.name, 'rules.md');
    assert.equal(imported.content, '范围\nOnly app.example.test');
    await assert.rejects(api.parseFile(file('rules.pdf', Buffer.from('text'))));
    await assert.rejects(api.parseFile(file('rules.txt', [0xff])));
    await assert.rejects(api.parseFile(file('rules.txt', [65, 0, 66])));
    await assert.rejects(api.parseFile(file('rules.txt', Buffer.alloc(65537, 65))));
});

test('project editor preserves and clears specification without parsing it as HTML', () => {
    const { api, elements } = runtime();
    elements['project-spec-name'] = { value: '' };
    elements['project-spec-content'] = { value: '' };
    elements['project-spec-file-name'] = { textContent: '', setAttribute() {}, removeAttribute() {} };
    api.fillEditor('project-spec', { name: 'rules.md', content: '<script>do not execute</script>' });
    assert.equal(api.readEditor('project-spec').content, '<script>do not execute</script>');
    assert.equal(elements['project-spec-file-name'].textContent, 'rules.md');
    api.fillEditor('project-spec', null);
    assert.equal(api.readEditor('project-spec').content, '');
    assert.notEqual(elements['project-spec-file-name'].textContent, 'rules.md');
});

test('task override is scoped to its project and is omitted when inheriting', () => {
    const { api } = runtime();
    api.setChatDraft('', 'project-a', { name: 'task.md', content: 'task rules' });
    const first = { projectId: 'project-a' };
    api.applyToChat(first);
    assert.equal(first.testingSpecification.content, 'task rules');
    const unrelated = { projectId: 'project-b' };
    api.applyToChat(unrelated);
    assert.equal(unrelated.testingSpecification, undefined);
    api.resetChat();
    const nextTask = { projectId: 'project-a' };
    api.applyToChat(nextTask);
    assert.equal(nextTask.testingSpecification, undefined);
});

test('accepted override is consumed while a rejected request remains retryable', () => {
    const { api } = runtime();
    api.setChatDraft('conversation-a', '', {name:'task.txt', content:'rules'});
    const failed = { conversationId:'conversation-a' };
    api.applyToChat(failed);
    const retry = { conversationId:'conversation-a' };
    api.applyToChat(retry);
    assert.equal(retry.testingSpecification.content, 'rules');
    api.acceptChatEvent(retry, {type:'message_saved',data:{conversationId:'conversation-a'}});
    const followup = { conversationId:'conversation-a' };
    api.applyToChat(followup);
    assert.equal(followup.testingSpecification, undefined);
});
