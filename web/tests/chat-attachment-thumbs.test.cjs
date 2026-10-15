const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');

const chatImages = fs.readFileSync('web/static/js/chat-images.js', 'utf8').replace(/\r\n/g, '\n');
const chat = fs.readFileSync('web/static/js/chat.js', 'utf8').replace(/\r\n/g, '\n');
const html = fs.readFileSync('web/templates/index.html', 'utf8');
const styles = fs.readFileSync('web/static/css/style.css', 'utf8');
const i18n = ['zh-CN', 'en-US', 'ru-RU'].map((loc) =>
    fs.readFileSync(path.join('web/static/i18n', loc + '.json'), 'utf8')
);

function loadChatImages(overrides = {}) {
    const fetched = [];
    const sandbox = {
        window: {},
        document: undefined,
        apiFetch: (url) => {
            fetched.push(url);
            return Promise.resolve(overrides.fetchResult || {
                ok: true,
                status: 200,
                blob: () => Promise.resolve({ size: 128, type: 'image/png' })
            });
        },
        URL: {
            createObjectURL: () => 'blob:mock-' + fetched.length,
            revokeObjectURL: () => {}
        },
        Promise,
        Map,
        console
    };
    sandbox.window.t = (key) => key;
    vm.createContext(sandbox);
    vm.runInContext(chatImages, sandbox);
    return { api: sandbox.window.csChatImages, fetched, sandbox };
}

test('解析用户消息里的图片附件并换算 chat_uploads 相对路径', () => {
    const { api } = loadChatImages();
    const content = [
        '看看这个登录页',
        '',
        '📎 login.png: /app/chat_uploads/2026-10-15/conv-1/login_120000_ab12cd.png',
        '📎 notes.txt: /app/chat_uploads/2026-10-15/conv-1/notes_120001_de34fg.txt',
        '📎 dup.png: /app/chat_uploads/2026-10-15/conv-1/login_120000_ab12cd.png',
        '📎 external.png: /var/tmp/external.png'
    ].join('\n');

    const items = api.parseImageAttachments(content);
    assert.equal(items.length, 1, '只应保留 1 张 chat_uploads 下的图片（去重、排除非图片与非 chat_uploads 路径）');
    assert.equal(items[0].name, 'login.png');
    assert.equal(items[0].relativePath, '2026-10-15/conv-1/login_120000_ab12cd.png');

    assert.equal(api.chatUploadsRelativePath('D:\\workspace\\chat_uploads\\2026-10-15\\conv-1\\a.png'), '2026-10-15/conv-1/a.png');
    assert.equal(api.chatUploadsRelativePath('chat_uploads/2026-10-15/conv-1/a.jpg'), '2026-10-15/conv-1/a.jpg');
    assert.equal(api.chatUploadsRelativePath('/var/tmp/a.png'), '');
    assert.equal(api.parseImageAttachments('无附件').length, 0);
});

test('渲染缩略图并通过鉴权接口拉取字节，失败时降级为文字状态', async () => {
    const { api, fetched, sandbox } = loadChatImages();

    const created = [];
    const makeEl = (tag) => {
        const el = {
            tagName: tag,
            children: [],
            classList: {
                _set: new Set(),
                add(c) { this._set.add(c); },
                remove(c) { this._set.delete(c); },
                contains(c) { return this._set.has(c); }
            },
            appendChild(child) {
                this.children.push(child);
                child.parentNode = this;
                return child;
            },
            removeChild(child) {
                this.children = this.children.filter((c) => c !== child);
                return child;
            },
            addEventListener() {},
            setAttribute() {},
            get firstChild() { return this.children[0] || null; }
        };
        created.push(el);
        return el;
    };
    sandbox.document = {
        createElement: makeEl,
        body: makeEl('body'),
        addEventListener() {},
        removeEventListener() {}
    };

    const container = makeEl('div');
    api.attach(container, '📎 login.png: /app/chat_uploads/2026-10-15/conv-1/login.png');
    assert.equal(container.children.length, 1, '应追加缩略图条');
    const strip = container.children[0];
    assert.match(strip.className, /message-attachment-thumbs/);
    assert.equal(strip.children.length, 1);

    await new Promise((resolve) => setImmediate(resolve));

    assert.equal(fetched.length, 1);
    assert.match(fetched[0], /^\/api\/chat-uploads\/download\?path=2026-10-15%2Fconv-1%2Flogin\.png$/, '相对路径需编码后交给鉴权下载接口');
    const thumb = strip.children[0];
    assert.ok(!thumb.classList.contains('is-loading'), '加载完成后应移除加载态');
    const img = thumb.children[0];
    assert.equal(img.tagName, 'img');
    assert.match(img.src, /^blob:/);
    assert.equal(img.loading, 'lazy', '缩略图应懒加载');

    // 无图片附件时不应产生任何节点
    const empty = makeEl('div');
    api.attach(empty, '📎 notes.txt: /app/chat_uploads/2026-10-15/conv-1/notes.txt');
    assert.equal(empty.children.length, 0);
});

test('缩略图拉取失败时显示不可用状态而不是空白', async () => {
    const { api, sandbox } = loadChatImages({
        fetchResult: { ok: false, status: 404, blob: () => Promise.resolve({ size: 0 }) }
    });
    const makeEl = (tag) => ({
        tagName: tag,
        children: [],
        classList: { _set: new Set(), add(c) { this._set.add(c); }, remove(c) { this._set.delete(c); }, contains(c) { return this._set.has(c); } },
        appendChild(child) { this.children.push(child); child.parentNode = this; return child; },
        removeChild(child) { this.children = this.children.filter((c) => c !== child); return child; },
        addEventListener() {},
        setAttribute() {},
        get firstChild() { return this.children[0] || null; }
    });
    sandbox.document = { createElement: makeEl, body: makeEl('body'), addEventListener() {}, removeEventListener() {} };

    const container = makeEl('div');
    api.attach(container, '📎 login.png: /app/chat_uploads/2026-10-15/conv-1/login.png');
    await new Promise((resolve) => setImmediate(resolve));

    const thumb = container.children[0].children[0];
    assert.ok(thumb.classList.contains('is-failed'));
    // 沙箱里 t() 返回键名本身（视作缺翻译），应回落到中文兜底文案
    assert.equal(thumb.children[0].textContent, '图片不可用');
});

test('对话界面接线：用户消息渲染缩略图、切换会话释放缓存、资源与样式已接入', () => {
    assert.match(
        chat,
        /role === 'user' && window\.csChatImages[\s\S]{0,120}window\.csChatImages\.attach\(contentWrapper, content\)/,
        'addMessage 应在用户消息里挂缩略图'
    );
    assert.match(
        chat,
        /previousConversationId !== conversationId && window\.csChatImages[\s\S]{0,80}window\.csChatImages\.reset\(\)/,
        '切换会话应释放 blob 缓存'
    );
    assert.match(html, /<script src="\/static\/js\/chat-images\.js\?v=[A-Za-z0-9._-]+"><\/script>/);
    assert.match(styles, /\.message-attachment-thumb\s*\{[^}]*cursor: zoom-in;/);
    assert.match(styles, /\.cs-image-lightbox\s*\{[^}]*position: fixed;/);

    for (const dict of i18n) {
        for (const key of ['attachmentImageLoading', 'attachmentImageFailed', 'attachmentImageClose']) {
            assert.ok(dict.includes(`"${key}"`), `i18n 缺少 ${key}`);
        }
    }
});
