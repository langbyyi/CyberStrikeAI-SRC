const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const assert = require('node:assert/strict');
const source = fs.readFileSync('web/static/js/skills.js', 'utf8');
const start = source.indexOf('async function selectSkillPackageFile(');
const end = source.indexOf('// 编辑skill', start);
function harness(dirty) {
    const inputs = {'skill-description': {disabled:false}, 'skill-content': {value:''}};
    let calls = 0;
    const ctx = {
        skillDescriptionDirty:dirty, skillFileDirty:false, skillActivePath:'SKILL.md',
        document:{getElementById:id => inputs[id] || null},
        _t:x => x, showNotification() {}, renderSkillPackageTree() {}, confirm:() => true,
        apiFetch:async () => {calls++; return {ok:true,json:async () => ({content:'text',skill:{content:'body'}})};},
    };
    vm.createContext(ctx);
    vm.runInContext(source.slice(start,end),ctx);
    return {ctx,inputs,calls:() => calls};
}
test('auxiliary file editing disables description and returning to SKILL.md enables it', async () => {
    const {ctx,inputs} = harness(false);
    await ctx.selectSkillPackageFile('test','references/example.md',{});
    assert.equal(inputs['skill-description'].disabled,true);
    await ctx.selectSkillPackageFile('test','SKILL.md',{});
    assert.equal(inputs['skill-description'].disabled,false);
});
test('unsaved description cannot disappear when switching files', async () => {
    const h = harness(true);
    await h.ctx.selectSkillPackageFile('test','references/example.md',{});
    assert.equal(h.ctx.skillActivePath,'SKILL.md');
    assert.equal(h.calls(),0);
});
