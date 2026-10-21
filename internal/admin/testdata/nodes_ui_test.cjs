const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const html = readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, 'admin inline script must exist');

function element() {
  const classes = new Set();
  return {
    value: '', checked: false, disabled: false, hidden: false, innerHTML: '', textContent: '', title: '', style: {},
    addEventListener() {}, removeAttribute() {}, focus() {},
    classList: {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      toggle(name, force) {
        const on = force === undefined ? !classes.has(name) : !!force;
        if (on) classes.add(name); else classes.delete(name);
        return on;
      },
      contains: name => classes.has(name),
    },
  };
}

// The fake server keeps nodes in its persisted order and sorts favorites first, like storage.SortNodes.
function createNodePage(names, handlers = {}) {
  const elements = new Map();
  const calls = [];
  const toasts = [];
  let serverNodes = names.map(name => ({ name, fav: false }));
  const sortServer = () => {
    serverNodes = [...serverNodes.filter(n => n.fav), ...serverNodes.filter(n => !n.fav)];
  };
  const defaults = {
    list: () => ({ ok: true, nodes: serverNodes.map(n => ({ ...n })) }),
    saveOrder: ({ order }) => {
      serverNodes = order.map(name => serverNodes.find(n => n.name === name));
      return { ok: true };
    },
    toggleFav: ({ name }) => {
      const node = serverNodes.find(n => n.name === name);
      node.fav = !node.fav;
      sortServer();
      return { ok: true, fav: node.fav };
    },
  };
  const context = vm.createContext({
    localStorage: { getItem: () => null },
    location: { origin: 'http://admin.test' },
    window: {},
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, element());
        return elements.get(id);
      },
      querySelectorAll: () => [],
    },
    setTimeout() {},
    clearTimeout() {},
    apiStub: async (action, data = {}) => {
      calls.push([action, data]);
      const handler = handlers[action] || defaults[action];
      assert.ok(handler, `unexpected api action ${action}`);
      return handler(data);
    },
    toastStub: (message, type) => toasts.push([message, type]),
  });
  vm.runInContext(script, context, { filename: 'admin-inline.js' });
  vm.runInContext('api = apiStub; toast = toastStub;', context);
  return {
    context,
    calls,
    toasts,
    el: id => context.document.getElementById(id),
    run: code => vm.runInContext(code, context),
    order: () => vm.runInContext('allNodes.map(n => n.name).join(",")', context),
    dirty: () => vm.runInContext('isNodeOrderDirty()', context),
    button: () => context.document.getElementById('saveOrderBtn'),
  };
}

test('drag order shows an unsaved state until it is saved', async () => {
  const page = createNodePage(['a', 'b', 'c']);
  await page.run('loadNodes()');
  assert.equal(page.dirty(), false);
  assert.equal(page.button().classList.contains('is-dirty'), false);
  assert.equal(page.button().innerHTML, '保存排序');
  assert.equal(page.run('window.onbeforeunload({ preventDefault() {} })'), undefined);

  page.run("moveNodeBeforeOrAfter('c', 'a', false); filterNodes();");
  assert.equal(page.order(), 'c,a,b');
  assert.equal(page.dirty(), true);
  assert.equal(page.button().classList.contains('is-dirty'), true);
  assert.match(page.button().innerHTML, /未保存/);
  assert.equal(page.run('window.onbeforeunload({ preventDefault() {} })'), '');

  // Another action reloads the list; the pending order survives with favorites still first.
  await page.run("toggleFav('b')");
  assert.equal(page.order(), 'b,c,a');
  assert.equal(page.dirty(), true);

  await page.run('doSaveOrder()');
  const saveCall = page.calls.find(([action]) => action === 'saveOrder');
  assert.deepEqual(Array.from(saveCall[1].order), ['b', 'c', 'a']);
  assert.equal(page.calls.at(-1)[0], 'list', 'saving reloads ranks from the server');
  assert.equal(page.order(), 'b,c,a');
  assert.equal(page.dirty(), false);
  assert.equal(page.button().classList.contains('is-dirty'), false);
  assert.deepEqual(page.toasts.at(-1), ['排序已保存', 'ok']);

  const callCount = page.calls.length;
  await page.run('doSaveOrder()');
  assert.equal(page.calls.length, callCount, 'a clean order is not resubmitted');

  // Moving a node back to its saved position clears the unsaved state.
  page.run("moveNodeBeforeOrAfter('a', 'c', false); filterNodes();");
  assert.equal(page.dirty(), true);
  page.run("moveNodeBeforeOrAfter('c', 'a', false); filterNodes();");
  assert.equal(page.order(), 'b,c,a');
  assert.equal(page.dirty(), false);
});

test('a failed save keeps the order pending', async () => {
  const page = createNodePage(['a', 'b'], { saveOrder: () => ({ ok: false, error: '写入失败' }) });
  await page.run('loadNodes()');
  page.run("moveNodeBeforeOrAfter('b', 'a', false); filterNodes();");
  await page.run('doSaveOrder()');
  assert.equal(page.calls.at(-1)[0], 'list', 'ranks written before the failure are reloaded');
  assert.equal(page.order(), 'b,a');
  assert.equal(page.dirty(), true);
  assert.deepEqual(page.toasts.at(-1), ['保存排序失败: 写入失败', 'err']);
});

test('renaming a node keeps its place in an unsaved order', async () => {
  let serverNames = ['a', 'b', 'c', 'd'];
  const page = createNodePage([], {
    list: () => ({ ok: true, nodes: serverNames.map(name => ({ name, fav: false })) }),
    // The server keeps the stored rank, so the renamed node stays in its saved position.
    save: ({ node }) => {
      serverNames = serverNames.map(name => name === node.oldName ? node.name : name);
      return { ok: true, node: { name: node.name } };
    },
    saveOrder: ({ order }) => {
      serverNames = [...order];
      return { ok: true };
    },
  });
  await page.run('loadNodes()');
  page.run("moveNodeBeforeOrAfter('d', 'a', false); filterNodes();");
  page.run("editingNode = allNodes.find(n => n.name === 'b');");
  page.el('f-name').value = 'b2';
  await page.run('saveNode()');
  assert.equal(page.order(), 'd,a,b2,c');
  assert.equal(page.dirty(), true);

  // Without a pending order the list simply follows the server.
  await page.run('doSaveOrder()');
  page.run("editingNode = allNodes.find(n => n.name === 'a');");
  page.el('f-name').value = 'a2';
  await page.run('saveNode()');
  assert.equal(page.order(), 'd,a2,b2,c');
  assert.equal(page.dirty(), false);
});

for (const { result, toast } of [
  { result: { ok: true }, toast: ['标签更新', 'ok'] },
  { result: { ok: false, error: 'database is closed' }, toast: ['设置标签失败: database is closed', 'err'] },
]) {
  test(`batch tag reloads nodes after ${result.ok ? 'success' : 'failure'}`, async () => {
    const page = createNodePage(['a', 'b'], { batchTag: () => result });
    page.context.prompt = () => 'hk';
    page.run("selectedNodes.add('a'); selectedNodes.add('b');");
    await page.run('batchTagSelected()');
    assert.equal(page.calls.at(-1)[0], 'list', 'nodes written before a failure are reloaded');
    assert.deepEqual(page.toasts.at(-1), toast);
  });
}

test('logging out drops the pending order', async () => {
  const page = createNodePage(['a', 'b']);
  await page.run('loadNodes()');
  page.run("moveNodeBeforeOrAfter('b', 'a', false); filterNodes(); resetProtectedUI();");
  assert.equal(page.dirty(), false);
});

test('favorite failures are reported', async () => {
  const page = createNodePage(['a'], { toggleFav: () => ({ ok: false, error: '节点不存在' }) });
  await page.run("toggleFav('a')");
  assert.deepEqual(page.toasts.at(-1), ['收藏失败: 节点不存在', 'err']);
  assert.equal(page.calls.some(([action]) => action === 'list'), false);
});

test('import failures stay visible in the dialog', async () => {
  const page = createNodePage([], {
    import: () => ({ ok: true, results: [
      { ok: true, name: 'a' },
      { ok: false, name: '<b>x</b>', error: 'name 不合法' },
      { ok: false, error: 'target 不能为空' },
    ] }),
  });
  page.el('importJson').value = '[{}, {}, {}]';
  page.run("showModal('importModal')");
  await page.run('doImport()');
  const output = page.el('importResults').innerHTML;
  assert.equal(page.el('importModal').style.display, 'flex');
  assert.match(output, /2 个节点未导入/);
  assert.match(output, /其余 1 个节点已导入/);
  assert.match(output, /第 2 项 &lt;b&gt;x&lt;\/b&gt;：name 不合法/);
  assert.match(output, /第 3 项：target 不能为空/);
  assert.doesNotMatch(output, /<b>x<\/b>/);
  assert.deepEqual(page.toasts.at(-1), ['导入完成: 1 成功 / 2 失败', 'err']);
  assert.equal(page.calls.at(-1)[0], 'list');

  page.run("openImportModal()");
  assert.equal(page.el('importResults').innerHTML, '');
});

for (const { input, index } of [
  { input: '[null, {}]', index: 1 },
  { input: '[{}, "text", {}]', index: 2 },
  { input: '[{}, {}, 42]', index: 3 },
  { input: '[{}, false]', index: 2 },
  { input: '[{}, []]', index: 2 },
  { input: '[{}, null, "text"]', index: 2 },
  { input: 'null', index: 1 },
]) {
  test(`import rejects non-object entries before submission: ${input}`, async () => {
    const page = createNodePage([]);
    page.el('importJson').value = input;
    page.el('importResults').innerHTML = 'previous import result';
    page.run("showModal('importModal')");
    await page.run('doImport()');
    assert.equal(page.calls.length, 0, 'invalid input must never reach the API');
    assert.equal(page.el('importModal').style.display, 'flex');
    assert.equal(page.el('importJson').value, input, 'keep the input available for correction');
    assert.equal(page.el('importResults').innerHTML, '');
    assert.deepEqual(page.toasts.at(-1), [`第 ${index} 项必须是节点对象，未执行导入`, 'err']);
  });
}

test('an empty import list is rejected before submission', async () => {
  const page = createNodePage([]);
  page.el('importJson').value = '[]';
  page.run("showModal('importModal')");
  await page.run('doImport()');
  assert.equal(page.calls.length, 0, 'the API would validate the request body as a node');
  assert.equal(page.el('importModal').style.display, 'flex');
  assert.equal(page.el('importResults').innerHTML, '');
  assert.deepEqual(page.toasts.at(-1), ['没有可导入的节点，未执行导入', 'err']);
});

test('malformed import JSON is reported without submitting or replacing the input', async () => {
  const page = createNodePage([]);
  page.el('importJson').value = '[{';
  page.run("showModal('importModal')");
  await page.run('doImport()');
  assert.equal(page.calls.length, 0);
  assert.equal(page.el('importJson').value, '[{');
  assert.equal(page.el('importModal').style.display, 'flex');
  assert.deepEqual(page.toasts.at(-1), ['JSON 格式错误', 'err']);
});

test('a fully successful import closes the dialog', async () => {
  const page = createNodePage([], { import: () => ({ ok: true, results: [{ ok: true, name: 'a' }] }) });
  page.el('importJson').value = '{"name":"a"}';
  page.run("showModal('importModal')");
  await page.run('doImport()');
  assert.equal(page.el('importModal').style.display, 'none');
  assert.equal(page.el('importResults').innerHTML, '');
  assert.deepEqual(page.toasts.at(-1), ['导入完成: 1 成功', 'ok']);
});

test('telegram test sends the unsaved form values and reports failures', async () => {
  const page = createNodePage([], { 'tg.test': () => ({ ok: false }) });
  page.el('tg-token').value = ' new-token ';
  page.el('tg-chat').value = '@channel';
  page.el('tg-reportTime').value = '09:30';
  await page.run('testTg()');
  const [, data] = page.calls.find(([action]) => action === 'tg.test');
  assert.equal(data.config.token, 'new-token');
  assert.equal(data.config.chat, '@channel');
  assert.equal(data.config.reportTime, '09:30');
  assert.deepEqual(page.toasts.at(-1), ['发送失败: 未知错误', 'err']);
});

for (const fn of ['testTg()', "testKeepalive('a', '', 30, 3, '03:00')"]) {
  test(`${fn} stays quiet when the session expired`, async () => {
    const stale = () => ({ ok: false, error: '', _status: 401, _stale: true });
    const page = createNodePage([], { 'tg.test': stale, 'keepalive.test': stale });
    await page.run(fn);
    assert.equal(page.toasts.length, 1, 'only the sending notice is shown');
    assert.equal(page.toasts[0][1], 'info');
  });
}
