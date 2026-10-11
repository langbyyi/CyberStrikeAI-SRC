const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const source = fs.readFileSync('web/static/js/notifications.js', 'utf8');
const start = source.indexOf('function renderNotificationList(');
const end = source.indexOf('function closeDropdown(', start);

async function clickView(actionable) {
    let click;
    let marked = 0;
    let refreshed = 0;
    let opened = 0;
    const item = {id: 'event-test', actionable};
    const list = {innerHTML: '', querySelectorAll: selector => selector.includes('view-btn') ? [{
        getAttribute: () => item.id,
        addEventListener: (_, callback) => { click = callback; },
    }] : []};
    const ctx = {
        document: {getElementById: () => list}, state: {items: [item]},
        MAX_RENDER_ITEMS: 20, htmlEscape: String, t: (_, fallback) => fallback,
        hasAction: () => true, formatTime: () => '', closeDropdown() {},
        openNotificationTarget: () => { opened++; },
        markItemsRead: async ids => { assert.equal(ids[0], item.id); marked++; return true; },
        refreshNotifications: async () => { refreshed++; },
    };
    vm.runInNewContext(source.slice(start, end), ctx);
    ctx.renderNotificationList([item]);
    await click({preventDefault() {}, stopPropagation() {}});
    return {marked, refreshed, opened};
}
test('viewing an informational event clears unread count through the server', async () => {
    assert.deepEqual(await clickView(false), {marked: 1, refreshed: 1, opened: 1});
});
test('viewing pending actionable notifications leaves approval unread state intact', async () => {
    assert.deepEqual(await clickView(true), {marked: 0, refreshed: 0, opened: 1});
});
