const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const source = fs.readFileSync('web/static/js/webshell.js', 'utf8');
function declaration(name) {
    const start = source.indexOf(`function ${name}(`);
    const end = source.indexOf('\nfunction ', start + 1);
    assert.ok(start >= 0 && end > start);
    return source.slice(start, end);
}
function harness() {
    const tree = { tree: {}, expanded: {}, loaded: {} };
    const treeEl = {innerHTML: '', querySelectorAll: () => []};
    const ctx = {
        Date, getWebshellTreeState: () => tree,
        getWebshellSelectedFile: () => '', webshellCurrentConn: {id: 'test'},
        document: { getElementById: id => id === 'webshell-dir-tree' ? treeEl : null },
        escapeHtml: value => String(value),
    };
    vm.createContext(ctx);
    for (const name of ['normalizeWebshellPath', 'getWebshellParentPath', 'normalizeLsMtime', 'modeToType', 'parseWindowsDirEntry', 'parseWebshellListItems', 'renderDirectoryTree']) {
        vm.runInContext(declaration(name), ctx);
    }
    return {ctx, tree, treeEl};
}
test('absolute Unix paths and roots survive normalization and parent navigation', () => {
    const {ctx} = harness();
    for (const [input, expected] of [['/tmp/', '/tmp'], ['/', '/'], ['/tmp/demo', '/tmp/demo'], ['tmp', 'tmp'], ['C:\\Temp', 'C:/Temp'], ['C:\\', 'C:/']]) {
        assert.equal(ctx.normalizeWebshellPath(input), expected);
    }
    assert.equal(ctx.getWebshellParentPath('/tmp'), '/');
    assert.equal(ctx.getWebshellParentPath('/'), '/');
    assert.equal(ctx.getWebshellParentPath('C:/Temp'), 'C:/');
});
test('ls failures never become clickable fake files', () => {
    const {ctx} = harness();
    for (const text of ["ls: 无法访问'tmp': 没有那个文件或目录", "ls: cannot access 'tmp': No such file or directory"]) {
        assert.equal(ctx.parseWebshellListItems(text).length, 0);
    }
    const items = ctx.parseWebshellListItems('drwxr-xr-x 2 root root 4096 Sep 26 12:00 demo\n-rw-r--r-- 1 root root 2 Sep 26 12:00 file');
    assert.equal(items.length, 2);
    assert.equal(items[0].name, 'demo');
    assert.equal(items[0].isDir, true);
});
test('directory tree preserves absolute ancestry and child paths', () => {
    const {ctx, tree, treeEl} = harness();
    ctx.renderDirectoryTree('/tmp/demo', [{name: 'file', isDir: false}], {id:'test'});
    assert.equal(tree.tree['/'][0].path, '/tmp');
    assert.equal(tree.tree['/tmp'][0].path, '/tmp/demo');
    assert.equal(tree.tree['/tmp/demo'][0].path, '/tmp/demo/file');
    assert.match(treeEl.innerHTML, /data-path="\/tmp\/demo\/file"/);
});
