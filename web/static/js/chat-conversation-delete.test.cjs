const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');

const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');

function functionSource(source, name, nextName) {
    const start = source.indexOf(`function ${name}(`);
    const plainEnd = source.indexOf(`function ${nextName}(`, start);
    const asyncEnd = source.indexOf(`async function ${nextName}(`, start);
    const end = asyncEnd !== -1 && (plainEnd === -1 || asyncEnd < plainEnd) ? asyncEnd : plainEnd;
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    return source.slice(start, end);
}

test('删除当前对话使旧导航和发送状态立即失效', () => {
    const source = functionSource(chat, 'resetDeletedCurrentConversation', 'deleteConversation');
    const calls = [];
    const context = {
        window: {
            currentConversationId: 'deleted-conversation',
            cancelScheduledChatConversationFromHash: () => calls.push('cancel-hash-restore'),
            cancelRunningTaskEventStream: (id) => calls.push(`cancel-task-stream:${id}`),
            clearChatHitlApprovalDock: () => calls.push('clear-hitl'),
            dispatchEvent: (event) => calls.push(`window-event:${event.type}:${event.detail.conversationId}`),
        },
        document: {
            getElementById: () => ({ innerHTML: 'old messages' }),
        },
        CustomEvent: class CustomEvent {
            constructor(type, init) {
                this.type = type;
                this.detail = init.detail;
            }
        },
        markChatConversationNavigation: (id, force) => calls.push(`navigate:${id}:${force}`),
        clearChatConversationHash: () => calls.push('clear-hash'),
        cancelPendingConversationLoad: () => calls.push('cancel-load'),
        detachLiveChatStreamForNavigation: (id, force) => calls.push(`detach:${id}:${force}`),
        renderChatWelcomeEmptyState: () => calls.push('render-empty'),
        addAttackChainButton: (id) => calls.push(`attack-chain:${id}`),
        updateChatPrimaryActionState: () => calls.push('update-action'),
        updateActiveConversation: () => calls.push('update-active'),
    };

    vm.runInNewContext(
        `let currentConversationId = 'deleted-conversation';\n${source}\n` +
        `result = resetDeletedCurrentConversation('deleted-conversation');\n` +
        `visibleId = currentConversationId;`,
        context,
    );

    assert.equal(context.result, true);
    assert.equal(context.visibleId, null);
    assert.equal(context.window.currentConversationId, '');
    assert.deepEqual(calls.slice(0, 6), [
        'navigate::true',
        'cancel-hash-restore',
        'clear-hash',
        'cancel-load',
        'detach::true',
        'cancel-task-stream:',
    ]);
    assert.ok(calls.includes('window-event:conversation-changed:'));
    assert.ok(calls.includes('render-empty'));
});

test('删除非当前对话不打断当前会话', () => {
    const source = functionSource(chat, 'resetDeletedCurrentConversation', 'deleteConversation');
    const context = {
        window: { currentConversationId: 'visible-conversation' },
    };
    vm.runInNewContext(
        `let currentConversationId = 'visible-conversation';\n${source}\n` +
        `result = resetDeletedCurrentConversation('another-conversation');\n` +
        `visibleId = currentConversationId;`,
        context,
    );

    assert.equal(context.result, false);
    assert.equal(context.visibleId, 'visible-conversation');
    assert.equal(context.window.currentConversationId, 'visible-conversation');
});
