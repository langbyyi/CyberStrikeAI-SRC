const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

test('工作流提供导入、导出和覆盖确认容器', () => {
    const html = fs.readFileSync('web/templates/index.html', 'utf8');
    const zh = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
    assert.match(html, /onclick="openWorkflowPackageImportModal\(\)"/);
    assert.match(html, /onclick="[^"]*exportCurrentWorkflowPackage\(\)"/);
    assert.match(html, /id="workflow-package-import-modal"/);
    assert.match(html, /id="workflow-package-overwrite-modal"/);
    assert.equal(zh.workflows.package.importLocal, '导入本地包');
});

test('本地包上传支持拖拽、键盘选择和选中文件反馈', () => {
    const html = fs.readFileSync('web/templates/index.html', 'utf8');
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const css = fs.readFileSync('web/static/css/style.css', 'utf8');
    assert.match(html, /id="workflow-package-dropzone"[\s\S]*?ondrop="onWorkflowPackageDrop\(event\)"/);
    assert.match(html, /onkeydown="onWorkflowPackageDropzoneKeydown\(event\)"/);
    assert.match(html, /id="workflow-package-selected-file"/);
    assert.match(workflows, /window\.onWorkflowPackageDrop = function \(event\)/);
    assert.match(workflows, /endsWith\('\.csapkg\.zip'\)/);
    assert.match(css, /\.workflow-package-dropzone\.is-dragging/);
});

test('工作流脚本调用包契约的全部端点与冲突错误码', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const client = fs.readFileSync('web/static/js/workflow-package-client.js', 'utf8');
    assert.match(workflows, /\/api\/workflows\/\$\{encodeURIComponent\(id\)\}\/package/);
    assert.match(client, /\/api\/workflow-package-inspections/);
    assert.match(client, /\/api\/workflow-package-imports/);
    assert.match(workflows, /WFPKG_CONFLICT_CHANGED/);
    assert.match(workflows, /WFPKG_INSPECTION_EXPIRED/);
});

test('预检无效包的契约错误码都有中文状态分支', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    [
        'WFPKG_INVALID_ARCHIVE',
        'WFPKG_UNSUPPORTED_FORMAT',
        'WFPKG_INVALID_MANIFEST',
        'WFPKG_CHECKSUM_MISMATCH',
        'WFPKG_MULTIPLE_WORKFLOWS',
        'WFPKG_WORKFLOW_INVALID'
    ].forEach((code) => assert.match(workflows, new RegExp(code)));
});

test('导入请求标识生成失败会进入中文错误处理', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    assert.match(workflows, /async function performWorkflowPackageImport\(request\)[\s\S]*?try\s*\{[\s\S]*?client\.createIdempotencyKey\(\)[\s\S]*?catch \(error\) \{\s*displayWorkflowPackageError\(error\)/);
});

test('工作流包动态状态同时提供中文和英文词条', () => {
    const zh = JSON.parse(fs.readFileSync('web/static/i18n/zh-CN.json', 'utf8'));
    const en = JSON.parse(fs.readFileSync('web/static/i18n/en-US.json', 'utf8'));
    const keys = [
        ['errors', 'invalidArchive'],
        ['conflict', 'idConflict'],
        ['summary', 'workflowName'],
        ['resolution', 'keepExisting'],
        ['result', 'overwritten']
    ];
    keys.forEach(([section, key]) => {
        assert.equal(typeof zh.workflows.package[section][key], 'string');
        assert.equal(typeof en.workflows.package[section][key], 'string');
    });
});

test('语言切换会刷新工作流包弹窗及其动态状态', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    assert.match(workflows, /function refreshWorkflowsI18n\(\)[\s\S]*?workflow-package-import-modal[\s\S]*?workflow-package-overwrite-modal[\s\S]*?renderWorkflowPackageInspection\(\)[\s\S]*?renderWorkflowPackageResolution\(\)/);
});

test('每次打开导入弹窗都会开始新的导入会话', () => {
    const workflows = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const start = workflows.indexOf('window.openWorkflowPackageImportModal = async function ()');
    const end = workflows.indexOf('window.closeWorkflowPackageImportModal = function ()', start);
    const openHandler = workflows.slice(start, end);
    assert.match(openHandler, /resetWorkflowPackageImport\(\);/);
    assert.doesNotMatch(openHandler, /restoreWorkflowPackageState\(\)/);
});

test('未写入的导入结果明确显示跳过或保留，不显示导入完成', () => {
    const vm = require('node:vm');
    const source = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const start = source.indexOf('    function renderWorkflowPackageImportResult(');
    const end = source.indexOf('    async function restoreWorkflowPackageState(', start);
    for (const [result, expected] of [['skipped_identical', '已跳过导入'], ['kept_existing', '已保留本地版本'], ['created', '导入已完成'], ['overwritten', '导入已完成'], ['renamed', '导入已完成']]) {
        const button = {};
        const c = vm.createContext({ workflowPackageText: (_, fallback) => fallback, renderWorkflowPackageResolution() {}, workflowPackageSubmitBtn: () => button });
        vm.runInContext(source.slice(start, end), c);
        c.renderWorkflowPackageImportResult({ result });
        assert.equal(button.textContent, expected);
        assert.equal(button.disabled, true);
    }
});

test('重复包确认明确区分跳过和保留，创建及覆盖入口保持原语义', () => {
    const vm = require('node:vm');
    const source = fs.readFileSync('web/static/js/workflows.js', 'utf8');
    const start = source.indexOf('    function renderWorkflowPackageResolution(');
    const end = source.indexOf('    function resetWorkflowPackageImport(', start);
    for (const [state, action, expected] of [['identical', 'keep_existing', '确认跳过导入'], ['id_conflict', 'keep_existing', '确认保留本地版本'], ['none', 'create', '确认创建'], ['id_conflict', 'overwrite', '继续确认覆盖'], ['id_conflict', 'rename', '确认另存']]) {
        const button = {};
        const c = vm.createContext({ workflowPackageState: { inspection: { conflict: { state } }, resolutionAction: action, riskChoicesVisible: true, newWorkflowId: 'copy' }, workflowPackageResolutionEl: () => ({}), workflowPackageSubmitBtn: () => button, workflowPackageClient: () => ({ allowedActions: () => [action] }), workflowPackageText: (_, fallback) => fallback, esc: value => value, workflowPackageResolutionCard: () => '', workflowPackageSetStep() {} });
        vm.runInContext(source.slice(start, end), c);
        c.renderWorkflowPackageResolution();
        assert.equal(button.textContent, expected);
        assert.equal(button.disabled, false);
    }
});
