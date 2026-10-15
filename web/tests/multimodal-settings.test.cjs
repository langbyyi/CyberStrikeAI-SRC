const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const html = fs.readFileSync('web/templates/index.html', 'utf8').replace(/\r\n/g, '\n');
const settings = fs.readFileSync('web/static/js/settings.js', 'utf8').replace(/\r\n/g, '\n');
const docs = fs.readFileSync('docs/zh-CN/VISION.md', 'utf8');
const i18n = ['zh-CN', 'en-US', 'ru-RU'].map((loc) =>
    fs.readFileSync(path.join('web/static/i18n', loc + '.json'), 'utf8')
);

function functionSource(source, name, nextName) {
    const start = source.indexOf(`function ${name}(`);
    const end = source.indexOf(`function ${nextName}(`, start);
    assert.notEqual(start, -1, `${name} should exist`);
    assert.notEqual(end, -1, `${nextName} should follow ${name}`);
    return source.slice(start, end);
}

// supports_vision 是多模态能力的唯一开关：UI 勾选必须能写进请求体、并能在切换通道时回显，
// 否则「主模型支持图片输入」对用户就是不可用的死开关。
test('AI 通道表单可读写 supports_vision', () => {
    const read = functionSource(settings, 'readAIChannelFromMainForm', 'writeAIChannelToMainForm');
    assert.match(read, /supports_vision: document\.getElementById\('openai-supports-vision'\)\?\.checked === true/);

    const write = functionSource(settings, 'writeAIChannelToMainForm', 'displayAIChannelName');
    assert.match(write, /supportsVisionEl\.checked = ch\.supports_vision === true/);

    // 从旧 openai 段播种通道时也要带上该字段
    const shape = functionSource(settings, 'ensureAIConfigShape', 'readAIChannelFromMainForm');
    assert.match(shape, /supports_vision: oa\.supports_vision === true/);

    assert.match(html, /<input type="checkbox" id="openai-supports-vision"/);
    assert.match(html, /data-i18n="settingsBasic\.supportsVision"/);
    assert.match(html, /data-i18n="settingsBasic\.supportsVisionHint"/);
});

test('supports_vision 的文案在三种语言里都存在且说明了兼容行为', () => {
    for (const dict of i18n) {
        assert.ok(dict.includes('"supportsVision"'), 'i18n 缺少 supportsVision');
        assert.ok(dict.includes('"supportsVisionHint"'), 'i18n 缺少 supportsVisionHint');
    }
    const zh = i18n[0];
    assert.match(zh, /未开启时图片只落盘为路径/);
    assert.match(zh, /analyze_image/);
});

// 配置面文档要覆盖开关与两条路径，避免「功能在但查不到」
test('文档覆盖开关、两条路径与真实验证方式', () => {
    assert.match(docs, /supports_vision/);
    assert.match(docs, /read_file/);
    assert.match(docs, /analyze_image/);
    assert.match(docs, /CSAI_LIVE_CLAUDE_BASE_URL/);
    assert.match(docs, /持久化边界/);
});
