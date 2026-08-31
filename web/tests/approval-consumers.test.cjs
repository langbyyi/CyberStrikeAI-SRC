const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

const ApprovalUIModel = require('../static/js/approval-ui-model.js');
const approvalUI = fs.readFileSync('web/static/js/approval-ui.js', 'utf8');
const dashboard = fs.readFileSync('web/static/js/dashboard.js', 'utf8');
const projects = fs.readFileSync('web/static/js/projects.js', 'utf8');
const monitor = fs.readFileSync('web/static/js/monitor.js', 'utf8');

function loadApprovalConsumers() {
    const window = {
        ApprovalUIModel: ApprovalUIModel,
        addEventListener: function () {},
    };
    const context = {
        window: window,
        document: { addEventListener: function () {} },
        URLSearchParams: URLSearchParams,
        console: console,
    };
    vm.runInNewContext(approvalUI, context, { filename: 'approval-ui.js' });
    return window;
}

test('统一待审批加载器分页加载全部项目，按实际返回数量推进 offset', async () => {
    const window = loadApprovalConsumers();
    const requests = [];
    const pages = [
        { total: 237, items: Array.from({ length: 200 }, (_unused, index) => ({ id: index + 1 })) },
        { total: 237, items: Array.from({ length: 37 }, (_unused, index) => ({ id: index + 201 })) },
    ];
    const items = await window.fetchAllPendingApprovals(async (url) => {
        requests.push(url);
        return { ok: true, json: async () => pages.shift() };
    });

    assert.deepEqual(Array.from(items, (item) => item.id), Array.from({ length: 237 }, (_unused, index) => index + 1));
    assert.deepEqual(requests, [
        '/api/approvals?status=pending_human&limit=200&offset=0',
        '/api/approvals?status=pending_human&limit=200&offset=200',
    ]);
});

test('统一待审批加载器以首个服务端 total 为快照，不追赶持续新增的记录', async () => {
    const window = loadApprovalConsumers();
    const requests = [];
    const pages = [
        { total: 2, items: [{ id: 1 }] },
        { total: 3, items: [{ id: 2 }] },
        { total: 4, items: [{ id: 3 }] },
    ];
    const items = await window.fetchAllPendingApprovals(async (url) => {
        requests.push(url);
        return { ok: true, json: async () => pages.shift() };
    }, 1);

    assert.deepEqual(Array.from(items, (item) => item.id), [1, 2]);
    assert.deepEqual(requests, [
        '/api/approvals?status=pending_human&limit=1&offset=0',
        '/api/approvals?status=pending_human&limit=1&offset=1',
    ]);
});

test('统一待审批加载器会钳制页大小，并在空页时停止而不循环', async () => {
    const window = loadApprovalConsumers();
    const requests = [];
    const items = await window.fetchAllPendingApprovals(async (url) => {
        requests.push(url);
        return { ok: true, json: async () => ({ total: 3, items: [] }) };
    }, 0);

    assert.deepEqual(Array.from(items), []);
    assert.deepEqual(requests, ['/api/approvals?status=pending_human&limit=1&offset=0']);
});

test('dashboard 使用服务端 pending total，而非首屏 items 数量', () => {
    const source = dashboard.match(/function getHitlPendingCount\(res\) \{[\s\S]*?\n\}/);
    assert.ok(source, '应提供 dashboard 待审批计数函数');
    const getHitlPendingCount = vm.runInNewContext(`(${source[0]})`, {
        window: { ApprovalUIModel: ApprovalUIModel },
    });
    assert.equal(getHitlPendingCount({ total: 237, items: Array(200) }), 237);
});

test('项目树和任务监控在运行时共享全量审批加载器，失败时以空集合对账', () => {
    assert.match(projects, /window\.fetchAllPendingApprovals\(apiFetch\)/);
    assert.match(monitor, /window\.fetchAllPendingApprovals\(apiFetch\)/);
    assert.doesNotMatch(projects, /api\/approvals\?status=pending_human&limit=200/);
    assert.doesNotMatch(monitor, /api\/approvals\?status=pending_human&limit=200/);
    assert.match(projects, /fetchAllPendingApprovals\(apiFetch\)[\s\S]{0,180}catch\(function \(\) \{ return \[\]; \}\)/);
    assert.match(monitor, /fetchAllPendingApprovals\(apiFetch\)[\s\S]{0,180}catch\(function \(\) \{ return \[\]; \}\)/);
});

test('统一待审批加载器受最大页数限制，堆积时不再无界拉取', async () => {
    const window = loadApprovalConsumers();
    const requests = [];
    const pages = Array.from({ length: 8 }, (_unused, pageIndex) => ({
        total: 5000,
        items: Array.from({ length: 200 }, (_unused2, index) => ({ id: pageIndex * 200 + index + 1 }))
    }));
    const items = await window.fetchAllPendingApprovals(async (url) => {
        requests.push(url);
        return { ok: true, json: async () => pages.shift() };
    });

    // 该加载器挂在 2 秒任务轮询上：默认最多 5 页（1000 条），
    // pending 异常堆积时每轮请求数必须有硬顶。
    assert.equal(requests.length, 5);
    assert.equal(items.length, 1000);
});
