const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const html = readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, 'admin inline script must exist');

function log(id, level = 'info') {
  return { id, level, time: `time-${id}`, line: `time-${id} [INFO] entry-${id}` };
}

function createLogView() {
  const timers = new Map();
  const requests = [];
  const elements = new Map();
  let nextTimer = 0;
  // Only the log console needs DOM children; no layout engine or real timers are used.
  const consoleEl = {
    children: [],
    scrollTop: 0,
    scrollHeight: 1000,
    clientHeight: 100,
    addEventListener() {},
    set innerHTML(value) {
      this.children = [...value.matchAll(/<div class="(?:log-line[^"\n]*|log-empty)">[\s\S]*?<\/div>/g)]
        .map(match => ({ outerHTML: match[0] }));
    },
    get innerHTML() { return this.children.map(child => child.outerHTML).join(''); },
    querySelector(selector) {
      assert.equal(selector, '.log-empty');
      return this.innerHTML.includes('class="log-empty"') ? {} : null;
    },
    appendChild(fragment) { this.children.push(...fragment.children); },
  };
  elements.set('logConsole', consoleEl);
  elements.set('logNewBadge', { textContent: '', hidden: true });
  const context = vm.createContext({
    AbortController,
    localStorage: { getItem: () => null },
    window: {},
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, { addEventListener() {}, textContent: '', hidden: true });
        return elements.get(id);
      },
      createDocumentFragment() {
        return { children: [], appendChild(child) { this.children.push(child); } };
      },
      createElement(tag) {
        assert.equal(tag, 'div');
        return { className: '', innerHTML: '', get outerHTML() { return `<div class="${this.className}">${this.innerHTML}</div>`; } };
      },
    },
    setTimeout(callback, delay) {
      const id = ++nextTimer;
      timers.set(id, { callback, delay });
      return id;
    },
    clearTimeout(id) { timers.delete(id); },
    requestSnapshot(action) {
      assert.equal(action, 'logs.list');
      return new Promise(resolve => requests.push(resolve));
    },
  });
  vm.runInContext(script, context, { filename: 'admin-inline.js' });
  vm.runInContext(`
    api = requestSnapshot;
    currentTab = 'logs';
    lastLogEntries = [${JSON.stringify(log(100))}];
    lastLogMeta = { newestId: 100, totalEntries: 1 };
    lastLogSeenId = lastLogStreamId = 100;
    renderLogs(lastLogEntries, lastLogMeta);
  `, context);
  return {
    consoleEl,
    elements,
    timers,
    context,
    load() { return vm.runInContext('loadLogs(false, 1, { skipRealtimeSync: true })', context); },
    stream(id, level) {
      vm.runInContext(`handleLogStreamEntry(${JSON.stringify(log(id, level))}, logStreamToken, logViewEpoch)`, context);
    },
    resolveSnapshot(ids, extra = {}) {
      assert.ok(requests.length, 'snapshot request must be pending');
      const newestId = Math.max(0, ...ids);
      requests.shift()({ ok: true, logs: ids.map(id => log(id)), newestId, streamId: newestId, page: 1, totalEntries: ids.length, ...extra });
    },
    failSnapshot(error = '服务不可用') {
      assert.ok(requests.length, 'snapshot request must be pending');
      requests.shift()({ ok: false, error, _status: 500 });
    },
    resolveStale() {
      assert.ok(requests.length, 'snapshot request must be pending');
      requests.shift()({ ok: false, error: '', _status: 401, _stale: true });
    },
    fireTimer(delay) {
      const [id, timer] = [...timers].find(([, entry]) => entry.delay === delay) || [];
      assert.ok(timer, `timer with delay ${delay} must be pending`);
      timers.delete(id);
      return timer.callback();
    },
    flushBatch() {
      for (const [id, timer] of [...timers]) {
        if (timer.delay !== 32) continue;
        timers.delete(id);
        timer.callback();
      }
    },
  };
}

function assertLogView(view, ids, unread) {
  assert.deepEqual(Array.from(vm.runInContext('lastLogEntries.map(logEntryId)', view.context)), ids);
  assert.equal(view.consoleEl.children.length, ids.length);
  for (const id of ids) {
    assert.equal(view.consoleEl.children.filter(child => child.outerHTML.includes(`entry-${id}</span>`)).length, 1);
  }
  assert.equal(vm.runInContext('pendingLogCount', view.context), unread);
  assert.equal(view.elements.get('logNewBadge').hidden, unread === 0);
  if (unread > 0) assert.equal(view.elements.get('logNewBadge').textContent, `↓ ${unread} 条新日志`);
}

for (const scenario of [
  { name: 'snapshot overlaps queued SSE', queued: [101], snapshot: [100, 101], expected: [100, 101], unread: 1 },
  { name: 'snapshot predates queued SSE', queued: [101], snapshot: [100], expected: [100, 101], unread: 1 },
  { name: 'snapshot partially overlaps the queue', queued: [101, 102], snapshot: [100, 101], expected: [100, 101, 102], unread: 2 },
  { name: 'snapshot includes an additional unseen entry', queued: [101], snapshot: [100, 101, 102], expected: [100, 101, 102], unread: 2 },
  { name: 'duplicate SSE delivery is counted once', queued: [101, 101], snapshot: [100, 101], expected: [100, 101], unread: 1 },
  { name: 'snapshot without SSE keeps normal unread counting', queued: [], snapshot: [100, 101], expected: [100, 101], unread: 1 },
  { name: 'sequence reset discards the old queue without a notification', queued: [101], snapshot: [1], expected: [1], unread: 0 },
]) {
  test(scenario.name, async () => {
    const view = createLogView();
    const pending = view.load();
    for (const id of scenario.queued) view.stream(id);
    assertLogView(view, [100], 0);
    assert.equal([...view.timers.values()].some(timer => timer.delay === 32), scenario.queued.length > 0);
    view.resolveSnapshot(scenario.snapshot);
    assert.equal(await pending, true);
    assertLogView(view, scenario.expected, scenario.unread);
    assert.equal(vm.runInContext('pendingStreamEntries.length', view.context), 0);
    assert.equal(vm.runInContext('logStreamFlushTimer', view.context), null);
    view.flushBatch();
    assertLogView(view, scenario.expected, scenario.unread);

    // A subsequent snapshot and duplicate SSE must not announce the same IDs again.
    const repeated = view.load();
    view.resolveSnapshot(scenario.expected);
    await repeated;
    view.stream(scenario.expected.at(-1));
    view.flushBatch();
    assertLogView(view, scenario.expected, scenario.unread);
  });
}

test('already-rendered SSE is not counted again alongside queued entries', async () => {
  const view = createLogView();
  const pending = view.load();
  view.stream(101);
  view.flushBatch();
  assertLogView(view, [100, 101], 1);
  view.stream(102);
  view.resolveSnapshot([100, 101, 102]);
  await pending;
  assertLogView(view, [100, 101, 102], 2);
  view.flushBatch();
  assertLogView(view, [100, 101, 102], 2);
});

test('following the bottom does not display an unread badge', async () => {
  const view = createLogView();
  view.consoleEl.scrollTop = 900;
  const pending = view.load();
  view.stream(101);
  view.resolveSnapshot([100, 101]);
  await pending;
  assertLogView(view, [100, 101], 0);
  assert.equal(view.consoleEl.scrollTop, view.consoleEl.scrollHeight);
});

test('filtered SSE does not contribute unread entries', async () => {
  const view = createLogView();
  vm.runInContext("currentLogLevelFilter = 'info'", view.context);
  const pending = view.load();
  view.stream(101, 'warn');
  view.stream(102, 'info');
  view.resolveSnapshot([100, 102]);
  await pending;
  assertLogView(view, [100, 102], 1);
});

// Replaces the network stream so tests observe when realtime updates would (re)start.
function stubRealtime(view, enabled) {
  vm.runInContext(`
    document.getElementById('logAutoRefresh').checked = ${enabled};
    realtimeStarts = 0;
    startLogStream = () => { realtimeStarts++; setLogStreamStatus('已连接', 'stream'); };
    toast = () => {};
  `, view.context);
  return {
    starts: () => vm.runInContext('realtimeStarts', view.context),
    status: () => view.elements.get('logStreamStatus').textContent,
    checked: () => view.elements.get('logAutoRefresh').checked,
  };
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('search pauses realtime logs and clearing it resumes them', async () => {
  const view = createLogView();
  const realtime = stubRealtime(view, true);
  vm.runInContext("setLogQuery('abc')", view.context);
  assert.equal(realtime.checked(), true);
  assert.equal(realtime.status(), '搜索中');
  let pending = view.fireTimer(300);
  view.resolveSnapshot([100]);
  await pending;
  assert.equal(realtime.starts(), 0);
  assert.equal(realtime.status(), '搜索中');

  vm.runInContext("setLogQuery('')", view.context);
  pending = view.fireTimer(300);
  view.resolveSnapshot([100]);
  await pending;
  assert.equal(realtime.starts(), 1);
  assert.equal(realtime.checked(), true);
});

test('history pages pause realtime logs and the latest page resumes them', async () => {
  const view = createLogView();
  const realtime = stubRealtime(view, true);
  vm.runInContext('currentLogHasOlder = true; currentLogTotalPages = 3;', view.context);
  vm.runInContext('loadOlderLogs()', view.context);
  assert.equal(realtime.status(), '历史页');
  view.resolveSnapshot([50], { page: 2, totalEntries: 6000 });
  await settle();
  assert.equal(vm.runInContext('currentLogPage', view.context), 2);
  assert.equal(realtime.checked(), true);
  assert.equal(realtime.starts(), 0);

  vm.runInContext('loadLatestLogs()', view.context);
  view.resolveSnapshot([100], { totalEntries: 6000 });
  await settle();
  assert.equal(realtime.starts(), 1);
});

test('realtime logs that the user turned off stay off on the latest page', async () => {
  const view = createLogView();
  const realtime = stubRealtime(view, false);
  vm.runInContext('currentLogHasOlder = true; currentLogTotalPages = 3;', view.context);
  vm.runInContext('loadOlderLogs()', view.context);
  view.resolveSnapshot([50], { page: 2, totalEntries: 6000 });
  await settle();
  vm.runInContext('loadLatestLogs()', view.context);
  view.resolveSnapshot([100], { totalEntries: 6000 });
  await settle();
  assert.equal(realtime.starts(), 0);
  assert.equal(realtime.status(), '已关闭');

  // Turning it on from a history page waits for the latest page instead of being rejected.
  vm.runInContext('loadOlderLogs()', view.context);
  view.resolveSnapshot([50], { page: 2, totalEntries: 6000 });
  await settle();
  vm.runInContext("document.getElementById('logAutoRefresh').checked = true; setLogAutoRefresh(true)", view.context);
  assert.equal(realtime.status(), '历史页');
  assert.equal(realtime.starts(), 0);
  vm.runInContext('loadLatestLogs()', view.context);
  view.resolveSnapshot([100], { totalEntries: 6000 });
  await settle();
  assert.equal(realtime.starts(), 1);
});

// Opens history page 2 with realtime paused, as the user would before returning to the latest page.
async function openHistoryPage(view) {
  vm.runInContext('currentLogHasOlder = true; currentLogTotalPages = 3;', view.context);
  vm.runInContext('loadOlderLogs()', view.context);
  view.resolveSnapshot([50], { page: 2, totalEntries: 6000 });
  await settle();
}

test('a failed load on the latest page still resumes realtime logs', async () => {
  const view = createLogView();
  const realtime = stubRealtime(view, true);
  await openHistoryPage(view);
  assert.equal(realtime.status(), '历史页');

  vm.runInContext('loadLatestLogs()', view.context);
  view.failSnapshot();
  await settle();
  assert.equal(realtime.starts(), 1);
  assert.equal(realtime.status(), '已连接');
});

test('a failed load after clearing the search still resumes realtime logs', async () => {
  const view = createLogView();
  const realtime = stubRealtime(view, true);
  vm.runInContext("setLogQuery('abc')", view.context);
  let pending = view.fireTimer(300);
  view.resolveSnapshot([100]);
  await pending;

  vm.runInContext("setLogQuery('')", view.context);
  pending = view.fireTimer(300);
  view.failSnapshot();
  await pending;
  assert.equal(realtime.starts(), 1);
  assert.equal(realtime.status(), '已连接');
});

test('a failed load keeps realtime paused on history pages and off when disabled', async () => {
  const paused = createLogView();
  const pausedRealtime = stubRealtime(paused, true);
  await openHistoryPage(paused);
  vm.runInContext('loadOlderLogs()', paused.context);
  paused.failSnapshot();
  await settle();
  assert.equal(pausedRealtime.starts(), 0);
  assert.equal(pausedRealtime.status(), '历史页');

  const disabled = createLogView();
  const disabledRealtime = stubRealtime(disabled, false);
  await openHistoryPage(disabled);
  vm.runInContext('loadLatestLogs()', disabled.context);
  disabled.failSnapshot();
  await settle();
  assert.equal(disabledRealtime.starts(), 0);
  assert.equal(disabledRealtime.status(), '已关闭');
});

test('a failed load for a superseded search leaves resuming to the debounced reload', async () => {
  const view = createLogView();
  const realtime = stubRealtime(view, true);
  vm.runInContext("setLogQuery('abc')", view.context);
  const searchLoad = view.fireTimer(300);
  // The search is cleared while its snapshot is still in flight, then that snapshot fails.
  vm.runInContext("setLogQuery('')", view.context);
  view.failSnapshot();
  await searchLoad;
  assert.equal(realtime.starts(), 0);

  const reload = view.fireTimer(300);
  view.resolveSnapshot([100]);
  await reload;
  assert.equal(realtime.starts(), 1);
});

test('a stale session response does not restart realtime logs', async () => {
  const view = createLogView();
  const realtime = stubRealtime(view, true);
  await openHistoryPage(view);
  vm.runInContext('loadLatestLogs()', view.context);
  view.resolveStale();
  await settle();
  assert.equal(realtime.starts(), 0);
});

test('the batch size limit still flushes immediately and counts entries once', async () => {
  const view = createLogView();
  const pending = view.load();
  const ids = Array.from({ length: 201 }, (_, i) => 100 + i);
  for (const id of ids.slice(1)) view.stream(id);
  assertLogView(view, ids, 200);
  assert.equal(vm.runInContext('pendingStreamEntries.length', view.context), 0);
  view.resolveSnapshot(ids);
  await pending;
  assertLogView(view, ids, 200);
});
