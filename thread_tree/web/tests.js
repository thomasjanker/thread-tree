'use strict';
// The "Tests" page: guided tests of Thread behaviour (scenario.py on the server). The user does the physical part
// (power off, battery out, pairing), the program records what the network does. Uses helpers of app.js and diag.js.

// which devices a test can be started on
const TEST_KINDS = [
  ['router_outage', 'router'], ['leader_outage', 'leader'], ['br_outage', 'br'], ['partition', 'router'],
  ['router_upgrade', 'router'], ['router_return', 'router'], ['device_rejoin', 'end'], ['commissioning', null],
];
const OUTAGE_TESTS = ['router_outage', 'leader_outage', 'br_outage', 'partition', 'router_upgrade'];

function testCandidates(what) {
  const nodes = Object.values(state.topo?.nodes || {}).filter(n => !n.placeholder);
  const isRouter = n => n.role === 'router' || n.role === 'leader';
  const pick = { router: isRouter, leader: n => n.role === 'leader', br: n => isRouter(n) && n.border_router, end: n => !isRouter(n) && !n.diag_self }[what];
  return nodes.filter(pick).sort((a, b) => nodeName(a).localeCompare(nodeName(b)));
}

async function testRequest(path, body) {
  const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.status);
  return data;
}

async function startTest(kind, target) {
  const name = target ? nodeName(state.topo.nodes[target]) : '';
  const vars = { title: t(`tests.${kind}.title`), name, do: fillTemplate(t(`tests.${kind}.do`), { name }, (k, v) => v) };
  if (!confirm(fillTemplate(t('tests.confirm'), vars, (k, v) => v))) return;
  try {
    await testRequest('/api/tests/start', { kind, target });
    notify(fillTemplate(t('tests.started'), vars, (k, v) => v));
    poll();
  } catch (err) { notify(`${t('set.error')}: ${err.message}`, true); }
}

async function stopTest() {
  try { await testRequest('/api/tests/stop'); poll(); } catch (err) { notify(`${t('set.error')}: ${err.message}`, true); }
}

async function loadTests() {
  state.tests = await fetch('/api/tests').then(r => r.json());
}

// ---- reports -----------------------------------------------------------------------------------------------

const rel = s => (s === null || s === undefined ? '–' : fmtDuration(s));
const fact = (label, value) => [h('dt', {}, label), h('dd', {}, value)];
const devLabel = (id, name) => (state.topo?.nodes[id] ? nodeLinkTo(id, nodeName(state.topo.nodes[id])) : (name || id || '–'));
const tfill = (key, params) => fillTemplate(t(key), params, (k, v) => v);

function outageFacts(r) {
  const out = [fact(t('diag.test.router_silent'), r.router_silent_after !== null ? tfill('diag.test.silent_after', { s: fmtDuration(r.router_silent_after) })
    : r.router_last_heard ? tfill('diag.test.still_heard', { ago: ago(r.router_last_heard) }) : '–'),
  fact(t('diag.test.links'), String(r.links_left)),
  fact(t('diag.test.leader'), r.leader_before === r.leader_now ? t('diag.test.leader_same')
    : tfill('diag.test.leader_changed', { a: routerLabel(r.leader_before), b: routerLabel(r.leader_now) })
      + (r.leader_changed_after !== null ? ' ' + tfill('tests.r.after', { s: rel(r.leader_changed_after) }) : ''))];
  if (r.kind === 'partition') {  // during a leader change the old and the new partition overlap briefly: no split
    out.push(fact(t('tests.r.partitions'), tfill('tests.r.partitions_v', { now: r.partitions_now, max: r.partitions_max })
      + (r.split_after !== null ? ' · ' + tfill('tests.r.split', { split: rel(r.split_after), merged: rel(r.merged_after) }) : '')));
  }
  if (r.kind === 'leader_outage') {
    out.push(fact(t('tests.r.partition_id'), `0x${Number(r.partition_before).toString(16)} → ${r.partition_now === null ? '–' : '0x' + Number(r.partition_now).toString(16)}`),
      fact(t('tests.r.version'), `${r.version_before ?? '–'} → ${r.version_now ?? '–'}`));
  }
  if (r.kind === 'br_outage') {
    out.push(fact(t('tests.r.br'), (r.br_now.length ? r.br_now.map(id => (state.topo?.nodes[id] ? nodeName(state.topo.nodes[id]) : id)).join(', ') : t('tests.r.br_none'))
      + (r.br_lost_after !== null ? ' · ' + tfill('tests.r.br_lost', { s: rel(r.br_lost_after) }) : '')));
  }
  if (r.kind === 'router_upgrade' || r.new_routers.length) {
    out.push(fact(t('tests.r.new_routers'), r.new_routers.length ? r.new_routers.map(x => `${x.name || (state.topo?.nodes[x.id] ? nodeName(state.topo.nodes[x.id]) : x.id)} (${x.rloc16}, ${tfill('tests.r.after', { s: rel(x.after) })})`).join(', ') : t('tests.r.none')));
  }
  return out;
}

function childrenTable(r) {
  if (!r.children.length) return h('p', { class: 'muted' }, t('diag.test.no_children'));
  const rows = r.children.map(c => h('tr', {}, h('td', {}, devLabel(c.id, c.name)), h('td', { class: 'mono' }, c.rloc16_before),
    h('td', {}, h('span', { class: `tag test-${c.status}` }, t('diag.test.status.' + c.status))),
    h('td', { class: 'num' }, rel(c.searched_after)), h('td', { class: 'num' }, rel(c.attached_after)),
    h('td', {}, c.new_parent === null ? '–' : routerLabel(c.new_parent))));
  return [h('p', {}, tfill('diag.test.summary', { moved: r.summary.moved, n: r.summary.children, longest: rel(r.summary.longest) })),
    h('div', { class: 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ...['diag.test.col.device', 'diag.test.col.before', 'diag.test.col.status', 'diag.test.col.searched', 'diag.test.col.attached', 'diag.test.col.parent'].map(k => h('th', {}, t(k))))),
      h('tbody', {}, rows)))];
}

function returnFacts(r) {
  return [fact(t('tests.r.on_at_start'), t(r.on_at_start ? 'tests.yes' : 'tests.no')),
    r.on_at_start ? fact(t('tests.r.went_off'), rel(r.silent_after)) : [],
    fact(t('tests.r.back'), rel(r.back_after)), fact(t('tests.r.adv'), rel(r.adv_after)),
    fact(t('tests.r.address'), `${r.rloc16_before || '–'} → ${r.rloc16_now || '–'}` + (r.same_id === null ? '' : ` (${t(r.same_id ? 'tests.r.same_id' : 'tests.r.new_id')})`)),
    fact(t('tests.r.attached'), `${r.children_before} → ${r.children_now}`)];
}

function rejoinFacts(r) {
  return [fact(t('diag.test.col.status'), h('span', { class: `tag test-${r.status === 'back' ? 'moved' : r.status === 'searching' ? 'searching' : 'waiting'}` }, t('tests.r.status.' + r.status))),
    fact(t('tests.r.went_off'), rel(r.silent_after)), fact(t('diag.test.col.searched'), rel(r.searched_after)),
    fact(t('diag.test.col.attached'), rel(r.attached_after)), fact(t('tests.r.requests'), r.requests ?? '–'),
    fact(t('tests.r.back'), rel(r.back_after)),
    fact(t('tests.r.parent'), `${routerLabel(r.parent_before)} → ${routerLabel(r.parent_now)}`)];
}

function commissioningTable(r) {
  const head = h('p', {}, tfill('tests.r.discoveries', { n: r.discoveries }));
  if (!r.devices.length) return [head, h('p', { class: 'muted' }, t('tests.r.no_devices'))];
  const rows = r.devices.map(d => h('tr', {}, h('td', {}, devLabel(d.id, d.name)), h('td', {}, roleChip(d.role)),
    h('td', { class: 'num' }, rel(d.first_seen_after)), h('td', { class: 'num' }, rel(d.discovery_after)),
    h('td', { class: 'num' }, rel(d.searched_after)), h('td', { class: 'num' }, rel(d.attached_after)),
    h('td', {}, d.parent === null ? '–' : routerLabel(d.parent))));
  return [head, h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ...['diag.test.col.device', 'col.role', 'tests.c.first', 'tests.c.discovery', 'diag.test.col.searched', 'diag.test.col.attached', 'diag.test.col.parent'].map(k => h('th', {}, t(k))))),
    h('tbody', {}, rows)))];
}

function testReport(r) {
  const kind = r.kind || 'router_outage';
  const name = r.target_name || r.router_name || r.target_rloc16 || r.router_rloc16 || '';
  const title = tfill(r.running ? 'tests.r.running' : 'tests.r.done', { title: t(`tests.${kind}.title`), name });
  const facts = OUTAGE_TESTS.includes(kind) ? outageFacts({ new_routers: [], ...r }) : kind === 'router_return' ? returnFacts(r)
    : kind === 'device_rejoin' ? rejoinFacts(r) : [];
  return h('div', { class: `card test${r.running ? ' running' : ''}` },
    h('div', { class: 'finding-head' }, h('strong', {}, title),
      r.running ? iconButton('stop', t('diag.test.stop'), { onclick: stopTest, disabled: state.config?.can_name === false ? 'disabled' : null })
        : h('span', { class: 'muted small' }, absTime(r.start))),
    r.running ? h('p', {}, tfill(`tests.${kind}.do`, { name })) : null,
    h('dl', { class: 'facts' }, fact(t('diag.test.duration'), fmtDuration(r.duration)), facts),
    OUTAGE_TESTS.includes(kind) ? childrenTable(r) : kind === 'commissioning' ? commissioningTable(r) : null,
    h('p', { class: 'muted small' }, t('diag.test.note')));
}

// ---- the page ------------------------------------------------------------------------------------------------

function testCard(kind, what, running) {
  state.testTarget = state.testTarget || {};
  const options = what ? testCandidates(what) : [];
  if (what && !options.some(n => n.id === state.testTarget[kind])) state.testTarget[kind] = options[0]?.id ?? null;
  const select = what ? h('select', { 'aria-label': t('tests.pick'), onchange: e => { state.testTarget[kind] = e.target.value; } },
    options.map(n => h('option', { value: n.id, selected: n.id === state.testTarget[kind] ? 'selected' : null },
      `${nodeName(n)}${n.rloc16 ? ` (${n.rloc16})` : ''}`))) : null;
  const blocked = running || state.config?.can_name === false || (what && !state.testTarget[kind]);
  return h('div', { class: 'card test-card' },
    h('h3', {}, t(`tests.${kind}.title`)), h('p', {}, t(`tests.${kind}.desc`)),
    what && !options.length ? h('p', { class: 'muted' }, t('tests.none')) :
      h('div', { class: 'toolbar' }, select ? h('label', {}, t('tests.pick'), ' ', select) : null,
        iconButton('play', t('tests.start'), { disabled: blocked ? 'disabled' : null, onclick: () => startTest(kind, what ? state.testTarget[kind] : null) })));
}

function renderTests() {
  const tests = state.tests;
  const running = !!tests?.running;
  return h('div', { class: 'diag' },
    h('div', { class: 'diag-head' }, h('h2', {}, t('view.tests'))),
    tests?.running ? testReport(tests.running) : null,
    h('p', { class: 'muted' }, t('tests.how')),
    h('div', { class: 'test-grid' }, TEST_KINDS.map(([kind, what]) => testCard(kind, what, running))),
    tests && tests.past.length ? section('diag.test.section',
      h('details', { class: 'minor', open: 'open' },
        h('summary', {}, tfill('diag.test.past', { n: tests.past.length })), tests.past.slice(0, 5).map(testReport))) : null);
}
