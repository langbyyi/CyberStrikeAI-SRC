const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');

function functionSource(source, name, nextName) {
    let start = source.indexOf(`function ${name}(`);
    if (start >= 6 && source.slice(start - 6, start) === 'async ') start -= 6;
    const plainEnd = source.indexOf(`function ${nextName}(`, start);
    const asyncEnd = source.indexOf(`async function ${nextName}(`, start);
    const end = asyncEnd !== -1 && (plainEnd === -1 || asyncEnd < plainEnd) ? asyncEnd : plainEnd;
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    return source.slice(start, end);
}

const QUEUE_FUNCTIONS = [
    ['chatQueueNewId', 'chatQueueStorageKey'],
    ['chatQueueStorageKey', 'chatQueueLoad'],
    ['chatQueueLoad', 'chatQueuePersist'],
    ['chatQueuePersist', 'chatQueueBasePlaceholder'],
    ['chatQueueBasePlaceholder', 'chatQueueApplyPlaceholder'],
    ['chatQueueApplyPlaceholder', 'chatQueueVisibleItems'],
    ['chatQueueVisibleItems', 'renderChatQueue'],
    ['enqueueChatMessage', 'removeChatQueueMessage'],
    ['removeChatQueueMessage', 'chatQueueSendNow'],
    ['chatQueueSendNow', 'syncChatQueueForVisibleConversation'],
    ['syncChatQueueForVisibleConversation', 'drainChatQueueIfIdle'],
    ['drainChatQueueIfIdle', 'clearChatInputAfterSend'],
];

function sourceUpTo(source, name, marker) {
    let start = source.indexOf(`function ${name}(`);
    if (start >= 6 && source.slice(start - 6, start) === 'async ') start -= 6;
    const end = source.indexOf(marker, start);
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${marker} should follow ${name}`);
    return source.slice(start, end);
}

function createQueueHarness(overrides = {}) {
    const store = new Map();
    const calls = [];
    const state = {
        visibleConversationId: overrides.visibleConversationId === undefined ? 'conv-1' : overrides.visibleConversationId,
        running: overrides.running === true,
        steerResponse: overrides.steerResponse || { ok: true, status: 200 },
        steerThrows: overrides.steerThrows === true,
    };
    const context = {
        console: { warn: () => {} },
        window: {},
        localStorage: {
            getItem: (k) => (store.has(k) ? store.get(k) : null),
            setItem: (k, v) => store.set(k, String(v)),
            removeItem: (k) => store.delete(k),
        },
        getVisibleChatConversationId: () => state.visibleConversationId,
        getCurrentChatTaskConversationId: () => state.visibleConversationId || 'conv-1',
        isCurrentChatTaskActive: () => state.running,
        apiFetch: async (url, options) => {
            calls.push(`fetch:${url}`);
            context.lastSteerBody = JSON.parse(options.body);
            if (state.steerThrows) throw new Error('network down');
            return {
                ok: state.steerResponse.ok,
                status: state.steerResponse.status,
                json: async () => overrides.steerBody || {},
            };
        },
        sendMessage: async (options) => {
            calls.push(`send:${(options && options.text) || ''}`);
            return true;
        },
        showChatToast: (message, type) => calls.push(`toast:${type}:${message}`),
        chatTranslate: (key, fallback) => fallback,
        renderChatQueue: () => calls.push('render-queue'),
        state,
        calls,
        store,
    };
    const sources = [
        sourceUpTo(chat, 'requestChatSteer', '// ---------- 运行中输入排队'),
        ...QUEUE_FUNCTIONS.map(([name, next]) => functionSource(chat, name, next)),
    ].join('\n');
    vm.runInNewContext(
        `const CHAT_QUEUE_STORAGE_PREFIX = 'cyberstrike_chat_queue_';\n` +
        `const CHAT_QUEUE_MAX_ITEMS = 20;\n` +
        `let chatQueuedMessages = [];\n` +
        `let chatQueueConversationId = '';\n` +
        `let chatQueueDispatching = false;\n` +
        `${sources}\n` +
        `this.api = {\n` +
        `  enqueue: enqueueChatMessage,\n` +
        `  remove: removeChatQueueMessage,\n` +
        `  sendNow: chatQueueSendNow,\n` +
        `  drain: drainChatQueueIfIdle,\n` +
        `  steer: requestChatSteer,\n` +
        `  sync: syncChatQueueForVisibleConversation,\n` +
        `  applyPlaceholder: chatQueueApplyPlaceholder,\n` +
        `  visible: chatQueueVisibleItems,\n` +
        `  items: () => chatQueuedMessages,\n` +
        `  conversationId: () => chatQueueConversationId,\n` +
        `};\n` +
        `this.QUEUE_PREFIX = CHAT_QUEUE_STORAGE_PREFIX;`,
        context,
    );
    return context;
}

test('运行中发送进入队列并持久化到该会话', () => {
    const h = createQueueHarness({ running: true });

    assert.equal(h.api.enqueue('熟悉一下'), true);

    assert.equal(h.api.items().length, 1);
    assert.equal(h.api.items()[0].text, '熟悉一下');
    assert.equal(h.api.conversationId(), 'conv-1');
    assert.ok(h.store.has(h.QUEUE_PREFIX + 'conv-1'), '队列应写入该会话的 localStorage');
    assert.ok(h.calls.includes('render-queue'), '入队后应重绘卡片');
});

test('空文本不入队', () => {
    const h = createQueueHarness();

    assert.equal(h.api.enqueue('   '), false);
    assert.equal(h.api.items().length, 0);
    assert.equal(h.calls.includes('render-queue'), false);
});

test('删除与编辑后的队列持久化一致', () => {
    const h = createQueueHarness();
    h.api.enqueue('第一条');
    h.api.enqueue('第二条');
    const firstId = h.api.items()[0].id;

    assert.equal(h.api.remove(firstId), true);

    const stored = JSON.parse(h.store.get(h.QUEUE_PREFIX + 'conv-1'));
    assert.deepEqual(stored.map((i) => i.text), ['第二条']);
    assert.equal(h.api.remove('not-exist'), false);
});

// vm 里创建的数组来自另一个 realm，strict deepEqual 会因原型不同而误报，统一用文本序列比较
function queueTexts(h) {
    return h.api.items().map((i) => i.text).join('|');
}

test('会话切换装载各自的队列，不串会话', () => {
    const h = createQueueHarness({ visibleConversationId: 'conv-1' });
    h.api.enqueue('属于 conv-1');

    h.state.visibleConversationId = 'conv-2';
    h.api.sync();

    assert.equal(h.api.conversationId(), 'conv-2');
    assert.equal(queueTexts(h), '', 'conv-2 不该看到 conv-1 的队列');
    assert.equal(h.api.visible().length, 0);

    h.state.visibleConversationId = 'conv-1';
    h.api.sync();
    assert.equal(queueTexts(h), '属于 conv-1', '回到 conv-1 应恢复其队列');
});

test('「立即」把队列消息作为执行中引导发送，成功后出队', async () => {
    const h = createQueueHarness({ running: true });
    h.api.enqueue('补充要求：只测 443');
    const id = h.api.items()[0].id;

    const ok = await h.api.sendNow(id);

    assert.equal(ok, true);
    assert.deepEqual(h.lastSteerBody, { conversationId: 'conv-1', message: '补充要求：只测 443' });
    assert.equal(h.api.items().length, 0, '发送成功后应出队');
    assert.ok(h.calls.some((c) => c === 'toast:info:已发送引导，将在当前步骤的安全点生效。'));
});

test('运行方式不支持引导时保留在队列并提示', async () => {
    const h = createQueueHarness({ running: true, steerResponse: { ok: false, status: 409 } });
    h.api.enqueue('补充要求');
    const id = h.api.items()[0].id;

    const ok = await h.api.sendNow(id);

    assert.equal(ok, false, '409 不应移除队列项');
    assert.equal(h.api.items().length, 1);
    assert.ok(h.calls.some((c) => c.startsWith('toast:info:') && c.includes('留在队列')), '409 应提示留在队列');
    assert.equal(h.calls.some((c) => c.startsWith('send:')), false);
});

test('引导请求失败保留在队列并可重试', async () => {
    const h = createQueueHarness({ running: true, steerThrows: true });
    h.api.enqueue('补充要求');
    const id = h.api.items()[0].id;

    const ok = await h.api.sendNow(id);

    assert.equal(ok, false);
    assert.equal(h.api.items().length, 1);
    assert.ok(h.calls.some((c) => c.startsWith('toast:error:')));
});

test('任务已结束时「立即」按普通消息发出', async () => {
    const h = createQueueHarness({ running: false });
    h.api.enqueue('排队消息');
    const id = h.api.items()[0].id;

    const ok = await h.api.sendNow(id);

    assert.equal(ok, true);
    assert.equal(h.calls.some((c) => c.startsWith('fetch:')), false, '无运行任务时不应调引导接口');
    assert.ok(h.calls.includes('send:排队消息'));
    assert.equal(h.api.items().length, 0);
});

test('任务结束后自动发送队首排队消息', async () => {
    const h = createQueueHarness({ running: true });
    h.api.enqueue('第一条');
    h.api.enqueue('第二条');

    assert.equal(await h.api.drain(), false, '运行中不得发送');
    assert.equal(h.api.items().length, 2);

    h.state.running = false;
    assert.equal(await h.api.drain(), true);

    assert.ok(h.calls.includes('send:第一条'));
    assert.equal(queueTexts(h), '第二条', '一次只发一条');
});

test('队列已存在时不重复并发起发送', async () => {
    const h = createQueueHarness({ running: false });
    h.api.enqueue('唯一一条');

    const first = h.api.drain();
    const second = h.api.drain();
    const result = await Promise.all([first, second]);

    assert.ok(h.calls.filter((c) => c.startsWith('send:')).length <= 1, '并发 drain 不得重复发送');
    assert.equal(h.api.items().length, 0);
    assert.ok(result.some(Boolean));
});

test('无排队消息时 drain 零副作用', async () => {
    const h = createQueueHarness({ running: false });

    assert.equal(await h.api.drain(), false);
    assert.equal(h.calls.some((c) => c.startsWith('send:') || c.startsWith('toast:')), false);
});

test('引导请求的结果分类映射到 HTTP 状态', async () => {
    const cases = [
        [{ ok: true, status: 200 }, 'ok'],
        [{ ok: false, status: 404 }, 'idle'],
        [{ ok: false, status: 409 }, 'unsupported'],
        // 403 是权限问题，不能与「运行方式不支持」混为一谈（否则文案误导用户去等任务结束）
        [{ ok: false, status: 403 }, 'forbidden'],
        [{ ok: false, status: 500 }, 'retry'],
    ];
    for (const [steerResponse, want] of cases) {
        const h = createQueueHarness({ steerResponse });
        assert.equal(await h.api.steer('conv-1', '补充'), want, `status=${steerResponse.status}`);
    }
    const h = createQueueHarness({ steerThrows: true });
    assert.equal(await h.api.steer('conv-1', '补充'), 'retry');
    assert.equal(await h.api.steer('', '补充'), 'unsupported');
    assert.equal(await h.api.steer('conv-1', '   '), 'unsupported');
});

test('权限不足时保留在队列并给专属提示，不误报为「不支持引导」', async () => {
    const h = createQueueHarness({ running: true, steerResponse: { ok: false, status: 403 } });
    h.api.enqueue('补充要求');
    const id = h.api.items()[0].id;

    const ok = await h.api.sendNow(id);

    assert.equal(ok, false);
    assert.equal(h.api.items().length, 1, '403 不应移除队列项');
    assert.ok(h.calls.some((c) => c.startsWith('toast:error:') && c.includes('权限')), '应提示权限不足');
    assert.equal(h.calls.some((c) => c.includes('不支持引导')), false, '不得误报为不支持引导');
});

test('占位符在有排队时切换为排队提示，清空后回落原值', () => {
    const h = createQueueHarness();
    const input = { placeholder: '输入测试目标或命令…  @ 选择工具', dataset: {} };
    h.api.sync();

    h.api.applyPlaceholder(input, '继续输入以排队后续修改');
    assert.equal(input.placeholder, '继续输入以排队后续修改');

    h.api.applyPlaceholder(input, null);
    assert.equal(input.placeholder, '输入测试目标或命令…  @ 选择工具');
});

test('运行中主按钮：输入框有内容为「发送」，为空才是「停止任务」', () => {
    const cases = [
        { running: true, value: '排队内容', wantStop: false },
        { running: true, value: '   ', wantStop: true },
        { running: true, value: '', wantStop: true },
        { running: false, value: '排队内容', wantStop: false },
        { running: false, value: '', wantStop: false },
    ];
    for (const tc of cases) {
        const input = { value: tc.value };
        const context = {
            isCurrentChatTaskActive: () => tc.running,
            document: { getElementById: (id) => (id === 'chat-input' ? input : null) },
        };
        vm.runInNewContext(
            `${functionSource(chat, 'chatPrimaryActionShowsStop', 'updateChatPrimaryActionState')}\n` +
            `this.result = chatPrimaryActionShowsStop();`,
            context,
        );
        assert.equal(
            context.result,
            tc.wantStop,
            `running=${tc.running} value=${JSON.stringify(tc.value)}`
        );
    }
});

// 回归：任务结束自动补发时，排队文本不得把用户为下一条消息暂存的附件一起发出并清空。
// sendMessage 的附件链路在这个 harness 里被 stub，故按仓库既有风格做源码切片断言。
test('代发排队消息不携带也不清空用户暂存的附件', () => {
    const start = chat.indexOf('async function sendMessage(');
    assert.notEqual(start, -1, 'sendMessage 应存在');
    const rest = chat.slice(start + 1);
    const nextTop = rest.match(/\n(?:async )?function /);
    const body = rest.slice(0, nextTop ? nextTop.index : rest.length);

    assert.match(body, /const useAttachments = !explicitText &&/, '附件判定必须受 explicitText 约束');
    assert.match(
        body,
        /if \(useAttachments\) \{\s*\n\s*chatAttachments = \[\];/,
        '清空附件必须受 useAttachments 约束，代发不得抹掉用户暂存的附件'
    );
    assert.doesNotMatch(body, /hasAttachments/, '不得再保留无条件的附件判定');
});
