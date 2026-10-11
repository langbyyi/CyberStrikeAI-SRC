const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const source = fs.readFileSync('web/static/js/c2.js', 'utf8');
const start = source.indexOf('C2.createProfile = function()');
const end = source.indexOf('C2.deleteProfile = function', start);

function harness(min, max) {
    let sent;
    let error;
    const values = {
        'c2-profile-name': 'test', 'c2-profile-ua': 'test-only-agent',
        'c2-profile-uris': '/test', 'c2-profile-jmin': min,
        'c2-profile-jmax': max, 'c2-profile-headers': '{"X-Test":"value"}',
    };
    const ctx = {
        C2: { closeModal() {}, loadProfiles() {} }, API_BASE: '/api/c2',
        c2t: x => x, showToast: (text, type) => { if (type === 'error') error = text; },
        document: { getElementById: id => ({value: values[id]}) },
        apiRequest: (method, url, data) => { sent = data; return Promise.resolve({}); },
    };
    vm.runInNewContext(source.slice(start, end), ctx);
    ctx.C2.createProfile();
    return {sent, error};
}

test('profile save uses API field names and preserves zero jitter', () => {
    const {sent, error} = harness('0', '100');
    assert.equal(error, undefined);
    assert.equal(sent.userAgent, 'test-only-agent');
    assert.equal(sent.jitterMinMs, 0);
    assert.equal(sent.jitterMaxMs, 100);
    assert.equal(sent.responseHeaders['X-Test'], 'value');
});

test('invalid jitter is rejected before sending profile', () => {
    for (const [min, max] of [['500', '100'], ['-1', '100'], ['1.5', '100'], ['x', '100']]) {
        const {sent, error} = harness(min, max);
        assert.equal(sent, undefined);
        assert.equal(error, 'c2.profiles.toastInvalidJitter');
    }
});
