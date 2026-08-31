const fs = require('node:fs');
const test = require('node:test');
const assert = require('node:assert/strict');

const chat = fs.readFileSync('web/static/js/chat.js', 'utf8');
const hitl = fs.readFileSync('web/static/js/hitl.js', 'utf8');

function functionSource(source, name, nextName) {
    const start = source.indexOf(`function ${name}(`);
    const end = source.indexOf(`function ${nextName}(`, start);
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    return source.slice(start, end);
}

test('旧版会话级默认审批人切换已退役，不得回潮', () => {
    // 裁决者由统一审批管线的策略决定，前端不再保存/上报 reviewer；
    // 该功能随旧 HITL 运行时一并退役，防止任何函数被重新引入。
    const retired = ['applyHitlDefaultReviewerFromServer', 'fetchHitlDefaultReviewer', 'putHitlDefaultReviewer',
        'initHitlDefaultReviewerFromServer', 'setHitlReviewerUI', 'onHitlReviewerChanged', 'hitlReviewerNormalize'];
    for (const name of retired) {
        assert.doesNotMatch(hitl, new RegExp(`function ${name}\\(`), `${name} should stay retired`);
    }
    assert.doesNotMatch(chat, /applyHitlDefaultReviewerFromServer|onHitlReviewerChanged|putHitlDefaultReviewer/);
});

