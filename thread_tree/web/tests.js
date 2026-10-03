'use strict';
// The "Tests" page: guided tests of Thread behaviour (scenario.py on the server). Uses the helpers of app.js and diag.js.

// ---- guided test: router outage ----------------------------------------------------------------------------

async function testRequest(path, body) {
  const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.status);
  return data;
}

async function startRouterTest(id) {
  const n = state.topo.nodes[id];
  const name = nodeName(n);
  const children = Object.values(state.topo.nodes).filter(c => c.parent === id).length;
  if (!confirm(fillTemplate(t('diag.test.confirm'), { name, n: children }, (k, v) => v))) return;
  try {
    await testRequest('/api/tests/router-outage', { router: id });
    notify(fillTemplate(t('diag.test.started'), { name }, (k, v) => v));
    poll();
  } catch (err) { notify(`${t('set.error')}: ${err.message}`, true); }
}

async function stopTest() {
  try { await testRequest('/api/tests/stop'); poll(); } catch (err) { notify(`${t('set.error')}: ${err.message}`, true); }
}

function testReport(r) {
  const name = r.router_name || r.router_rloc16;
  const rel = s => (s === null || s === undefined ? '–' : fmtDuration(s));
  const silent = r.router_silent_after !== null ? fillTemplate(t('diag.test.silent_after'), { s: fmtDuration(r.router_silent_after) }, (k, v) => v)
    : r.router_last_heard ? fillTemplate(t('diag.test.still_heard'), { ago: ago(r.router_last_heard) }, (k, v) => v) : '–';
  const leader = r.leader_before === r.leader_now ? t('diag.test.leader_same')
    : fillTemplate(t('diag.test.leader_changed'), { a: routerLabel(r.leader_before), b: routerLabel(r.leader_now) }, (k, v) => v);
  const rows = r.children.map(c => h('tr', {},
    h('td', {}, state.topo.nodes[c.id] ? nodeLinkTo(c.id, nodeName(state.topo.nodes[c.id])) : (c.name || c.id)),
    h('td', { class: 'mono' }, c.rloc16_before),
    h('td', {}, h('span', { class: `tag test-${c.status}` }, t('diag.test.status.' + c.status))),
    h('td', { class: 'num' }, rel(c.searched_after)), h('td', { class: 'num' }, rel(c.attached_after)),
    h('td', {}, c.new_parent === null ? '–' : routerLabel(c.new_parent))));
  return h('div', { class: `card test${r.running ? ' running' : ''}` },
    h('div', { class: 'finding-head' }, h('strong', {}, fillTemplate(t(r.running ? 'diag.test.title_running' : 'diag.test.title_done'), { name }, (k, v) => v)),
      r.running ? h('button', { type: 'button', onclick: stopTest, disabled: state.config?.can_name === false ? 'disabled' : null }, t('diag.test.stop'))
        : h('span', { class: 'muted small' }, absTime(r.start))),
    r.running ? h('p', {}, t('diag.test.instructions')) : null,
    h('dl', { class: 'facts' },
      h('dt', {}, t('diag.test.duration')), h('dd', {}, fmtDuration(r.duration)),
      h('dt', {}, t('diag.test.router_silent')), h('dd', {}, silent),
      h('dt', {}, t('diag.test.links')), h('dd', {}, String(r.links_left)),
      h('dt', {}, t('diag.test.leader')), h('dd', {}, leader)),
    r.children.length ? [h('p', {}, fillTemplate(t('diag.test.summary'), { moved: r.summary.moved, n: r.summary.children, longest: rel(r.summary.longest) }, (k, v) => v)),
      h('div', { class: 'tablewrap' }, h('table', {},
        h('thead', {}, h('tr', {}, ...['diag.test.col.device', 'diag.test.col.before', 'diag.test.col.status', 'diag.test.col.searched', 'diag.test.col.attached', 'diag.test.col.parent'].map(k => h('th', {}, t(k))))),
        h('tbody', {}, rows)))] : h('p', { class: 'muted' }, t('diag.test.no_children')),
    h('p', { class: 'muted small' }, t('diag.test.note')));
}

async function loadTests() {
  state.tests = await fetch('/api/tests').then(r => r.json());
}

// the router outage test: pick a router, start, follow the report
function routerTestCard(tests) {
  const routers = Object.values(state.topo?.nodes || {}).filter(n => !n.placeholder && (n.role === 'router' || n.role === 'leader'))
    .sort((a, b) => nodeName(a).localeCompare(nodeName(b)));
  if (!routers.some(r => r.id === state.testRouter)) state.testRouter = routers[0]?.id ?? null;
  const children = id => Object.values(state.topo.nodes).filter(c => c.parent === id).length;
  const select = h('select', { 'aria-label': t('tests.router.pick'), onchange: e => { state.testRouter = e.target.value; } },
    routers.map(r => h('option', { value: r.id, selected: r.id === state.testRouter ? 'selected' : null },
      `${nodeName(r)} (${r.rloc16}, ${fillTemplate(t('tests.router.children'), { n: children(r.id) }, (k, v) => v)})`)));
  const busy = !!tests?.running || state.config?.can_name === false || !state.testRouter;
  return h('div', { class: 'card test-card' },
    h('h3', {}, t('tests.router.title')),
    h('p', {}, t('tests.router.desc')),
    routers.length ? h('div', { class: 'toolbar' }, h('label', {}, t('tests.router.pick'), ' ', select),
      h('button', { type: 'button', disabled: busy ? 'disabled' : null, onclick: () => startRouterTest(state.testRouter) }, t('tests.router.start')))
      : h('p', { class: 'muted' }, t('tests.none_routers')),
    tests?.running ? null : h('p', { class: 'muted small' }, t('tests.router.how')));
}

function renderTests() {
  const tests = state.tests;
  return h('div', { class: 'diag' },
    h('div', { class: 'diag-head' }, h('h2', {}, t('view.tests'))),
    tests?.running ? testReport(tests.running) : null,
    routerTestCard(tests),
    tests && tests.past.length ? section('diag.test.section',
      h('details', { class: 'minor', open: 'open' },
        h('summary', {}, fillTemplate(t('diag.test.past'), { n: tests.past.length }, (k, v) => v)), tests.past.slice(0, 5).map(testReport))) : null,
    h('p', { class: 'muted small' }, t('tests.planned')));
}

