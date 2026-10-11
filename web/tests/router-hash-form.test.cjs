// The console's own hash form is `#system-update`, not `#/system-update` - and before this,
// typing or sharing the slashed form silently did nothing: the id missed the whitelist and
// the router stayed on whatever page had loaded, with no message anywhere. Since every bit of
// documentation (and every human habit) writes the slashed form, the router now normalizes it
// instead of rejecting it.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROUTER = fs.readFileSync(path.join(__dirname, '../static/js/router.js'), 'utf8');

test('both hash entry points strip a leading slash before the whitelist', () => {
	// Two parsers exist (initial load and hash change); fixing only one is how this class of
	// bug survives a "works for me" check.
	const sites = [...ROUTER.matchAll(/let pageId = hashParts\[0\]([^\n]*)/g)];
	assert.ok(sites.length >= 2, `expected two hash parsers, found ${sites.length}`);
	for (const s of sites) {
		assert.match(s[1], /replace\(\/\^#\?\\\/\//, 'this parser does not normalize the slashed form: ' + s[0]);
	}
});

test('the slashed form resolves to the same page id as the plain one', () => {
	// Mirrors the router exactly: it takes location.hash.slice(1), so the '#' is already gone
	// before the split. A helper here that expected the '#' would "pass" the wrong rule.
	const normalize = (fullHash) => {
		const raw = fullHash.startsWith('#') ? fullHash.slice(1) : fullHash;
		return raw.split('?')[0].replace(/^#?\//, '');
	};
	for (const page of ['system-update', 'plugins-management', 'dashboard', 'chat']) {
		assert.strictEqual(normalize('#' + page), page);
		assert.strictEqual(normalize('#/' + page), page);
	}
	// Query-carrying hashes must keep working the same way they did.
	assert.strictEqual(normalize('#chat?conversation=abc'), 'chat');
});

test('the docs use a form the router actually accepts', () => {
	const docs = ['../../docs/zh-CN/developer-guide.md']; // 本分支不收录 docs/en-US
	for (const rel of docs) {
		const p = path.join(__dirname, rel);
		const text = fs.readFileSync(p, 'utf8');
		// Not a style preference: `#/x` was a dead link when it was written, so a doc that
		// tells an operator to open it is telling them to open nothing.
		assert.ok(!/#\/system-update/.test(text), `${rel} still advertises the dead #/system-update form`);
		assert.match(text, /#system-update/, `${rel} must name the form that works`);
	}
});
