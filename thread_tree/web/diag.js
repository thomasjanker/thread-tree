'use strict';
// The "Diagnosis" view: network overview with findings, a sortable node table, and a detail page per node.
// Depends on the helpers of app.js (h, s, t, state, nodeName, roleChip, ago, ...), format.js and charts.js.

const SEVERITIES = ['ok', 'info', 'warn', 'crit'];
const sevRank = sev => SEVERITIES.indexOf(sev);
const RSSI_WEAK_DBM = -85;  // same threshold as the server uses for its finding
const LINK_LOSS_HIGH = 25;  // percent of frames lost: the server's threshold for a lossy link

// ---- formatting that needs translations or topology ----------------------------------------------------

function routerLabel(id) {
  return id === null || id === undefined ? '–' : `0x${(id << 10).toString(16).padStart(4, '0')}`;
}

function paramText(key, value) {
  if (value === null || value === undefined) return '–';
  if (key.endsWith('_node')) {
    const n = state.topo && state.topo.nodes[value];
    return n ? nodeName(n) : String(value);
  }
  if (key === 'since') return ago(value);
  if (key === 'rate') return fmtPct(value);
  if (key === 'msg_rate') return fmtPct(value, 1);
  if (key === 'rssi') return fmtDbm(value);
  if (['mean', 'seconds', 'age', 'timeout', 'longest', 'usual', 'interval'].includes(key)) return fmtDuration(value);
  if (key === 'chosen' || key === 'best') return routerLabel(value);
  if (key.endsWith('_margin')) return `${value} dB`;
  return String(value);
}

function findingText(f) {
  return {
    title: t(`finding.${f.code}.title`),
    text: fillTemplate(t(`finding.${f.code}.text`), f.params, paramText),
    hint: fillTemplate(t(`finding.${f.code}.hint`), f.params, paramText),
  };
}

// events of the standard checks and of the network as a whole
function specialEventText(kind, p) {
  const tpl = (key, params) => fillTemplate(t(key), params, (k, v) => v);
  const r = v => (v === null || v === undefined ? '–' : routerLabel(v));
  const pid = v => (v === null || v === undefined ? '–' : `0x${Number(v).toString(16)}`);
  const devs = ids => (ids || []).map(id => (state.topo?.nodes[id] ? nodeName(state.topo.nodes[id]) : id)).join(', ') || '–';
  switch (kind) {
    case 'parent_choice': return tpl('event.parent_choice', { chosen: r(p.chosen), best: r(p.best), cm: p.chosen_margin, bm: p.best_margin });
    case 'reboot': return tpl(p.how === 'reset' ? 'event.reboot.reset' : 'event.reboot.skip', { a: p.from, b: p.to });
    case 'supervision_gap': return tpl('event.supervision_gap', { parent: r(p.parent), seconds: fmtDuration(p.seconds), interval: fmtDuration(p.interval) });
    case 'netdata_lag': return tpl('event.netdata_lag', { seconds: fmtDuration(p.seconds), version: p.version, current: p.current });
    case 'adv_gap': return tpl('event.adv_gap', { seconds: fmtDuration(p.seconds) });
    case 'attach_unanswered': return tpl('event.attach_unanswered', { router: r(p.router) });
    case 'leader_change': return tpl('event.leader_change', { partition: pid(p.partition), a: r(p.from), b: r(p.to) });
    case 'partition_new': return tpl('event.partition_new', { partition: pid(p.partition), leader: r(p.leader) });
    case 'partitions': return p.count > 1 ? tpl('event.partitions.split', { n: p.count }) : t('event.partitions.merged');
    case 'br_change': return tpl('event.br_change', { added: devs(p.added), removed: devs(p.removed) });
    case 'routers': return tpl('event.routers', { a: p.before, b: p.count });
    case 'netdata_version': return tpl('event.netdata_version', { version: p.version, partition: pid(p.partition) });
    default: return null;
  }
}

function eventText(ev) {
  const p = ev.params || {};
  const value = (key, v) => {
    if (v === null || v === undefined) return '–';
    if (key === 'parent') return `${t('event.router')} ${routerLabel(v)}`;
    if (key === 'partition') return `0x${Number(v).toString(16)}`;
    return key === 'role' ? roleLabel(v) : String(v);
  };
  const params = {};
  if (ev.kind === 'poll_gap') return fillTemplate(t('event.poll_gap'), { seconds: fmtDuration(p.seconds), usual: fmtDuration(p.usual) }, (k, v) => v);
  if (ev.kind === 'parent_search') return t('event.parent_search') + (p.parent === null || p.parent === undefined ? ''
    : fillTemplate(t('event.parent_search.attached'), { router: routerLabel(p.parent) }, (k, v) => v));
  if (ev.kind === 'attached') return fillTemplate(t('event.attached'),
    { to: p.to === null || p.to === undefined ? '–' : routerLabel(p.to), seconds: fmtDuration(p.seconds), requests: p.requests }, (k, v) => v);
  const special = specialEventText(ev.kind, p);
  if (special !== null) return special;
  if (ev.kind === 'first_seen') params.how = t('how.' + p.how);
  else if (ev.kind === 'mac_learned') params.rloc16 = p.rloc16;
  else if ('from' in p) { params.from = value(ev.kind, p.from); params.to = value(ev.kind, p.to); }
  const text = fillTemplate(t('event.' + ev.kind), params, (k, v) => v);
  return ev.kind === 'parent' && p.rloc16_from !== undefined
    ? text + fillTemplate(t('event.parent.addr'), { a: p.rloc16_from ?? '–', b: p.rloc16_to ?? '–' }, (k, v) => v) : text;
}

function absTime(ts) {
  return ts ? new Date(ts * 1000).toLocaleString(state.lang, { dateStyle: 'short', timeStyle: 'medium' }) : '–';
}

function sevChip(sev) { return h('span', { class: `sev sev-${sev}` }, t('sev.' + sev)); }
function healthDot(sev) { return h('span', { class: `dot dot-${sev || 'ok'}`, title: t('sev.' + (sev || 'ok')) }); }

function nodeLinkTo(id, label) {
  return h('a', { href: '#', class: 'nodelink', onclick: e => { e.preventDefault(); openDiagNode(id); } }, label);
}

// ---- navigation and data --------------------------------------------------------------------------------

function openDiagNode(id) {
  state.view = 'diag';
  state.diagNode = id;
  state.diagDetail = null;
  state.selected = null;
  render();
  poll();
  window.scrollTo(0, 0);
  document.getElementById('view').scrollTo(0, 0);
}

function closeDiagNode() {
  state.diagNode = null;
  state.diagDetail = null;
  render();
}

async function loadDiagnostics() {
  const requests = [fetch('/api/diagnostics').then(r => r.json())];
  if (state.diagNode) requests.push(fetch(`/api/nodes/${encodeURIComponent(state.diagNode)}/diagnostics`));
  const [report, detailRes] = await Promise.all(requests);
  state.diag = report;
  if (detailRes) {
    if (detailRes.ok) state.diagDetail = await detailRes.json();
    else { state.diagNode = null; state.diagDetail = null; }  // the node is gone (e.g. after a rebuild)
  }
}

async function askNow() {
  try {
    const res = await fetch('/api/diagnostics/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.status);
    notify(t('diag.active.asked'));
    poll();
  } catch (err) { notify(`${t('set.error')}: ${err.message}`, true); }
}

async function setDiagEnabled(enabled) {
  try {
    const res = await fetch('/api/diagnostics/enabled', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || res.status);
    notify(t(enabled ? 'diag.active.switched_on' : 'diag.active.switched_off'));
    poll();
  } catch (err) { notify(`${t('set.error')}: ${err.message}`, true); }
}

// ---- small building blocks ------------------------------------------------------------------------------

const card = (title, value, sub, extra) => h('div', { class: 'card' },
  h('div', { class: 'card-title' }, title), h('div', { class: 'card-value' }, value),
  sub ? h('div', { class: 'card-sub' }, sub) : null, extra || null);

const tile = (label, value, hint) => h('div', { class: 'tile', title: hint || null },
  h('div', { class: 'tile-value' }, value), h('div', { class: 'tile-label' }, label));

const section = (titleKey, ...children) => h('section', { class: 'dsec' }, h('h3', {}, t(titleKey)), ...children);

function findingRow(f, nodeId) {
  const text = findingText(f);
  return h('div', { class: `finding sev-${f.severity}` },
    h('div', { class: 'finding-head' }, sevChip(f.severity), h('strong', {}, text.title),
      nodeId ? nodeLinkTo(nodeId, nodeName(state.topo.nodes[nodeId])) : null),
    h('p', {}, text.text),
    h('details', {}, h('summary', {}, t('diag.hint')), h('p', {}, text.hint)));
}

// ---- overview ------------------------------------------------------------------------------------------

function activeCard(active) {
  if (!active || !active.enabled) return card(t('diag.card.active'), t('diag.active.off'), t('diag.active.off.sub'));
  const name = f => (f.node && state.topo.nodes[f.node] ? nodeName(state.topo.nodes[f.node]) : f.rloc16);
  const sub = active.state === 'error' ? active.error
    : active.ts ? fillTemplate(t('diag.active.sub'), { ago: ago(active.ts), routers: active.routers ?? 0, children: active.children ?? 0 }, (k, v) => v) : null;
  const silent = active.failures || [];
  return card(t('diag.card.active'), t('diag.state.' + String(active.state || 'starting').replace(/ /g, '_')), sub,
    h('div', { class: 'card-actions' },
      iconButton('refresh', t('diag.active.ask'), { disabled: state.config?.can_name === false || active.paused ? 'disabled' : null, onclick: askNow }),
      active.paused ? h('p', { class: 'card-sub' }, t('diag.active.paused_note')) : null,
      silent.length ? h('p', { class: 'card-sub' }, fillTemplate(t('diag.active.failures'), { n: silent.length, names: silent.map(name).join(', ') }, (k, v) => v)) : null));
}

function overviewCards(sum) {
  const topo = state.topo;
  const names = ids => ids.map(id => (topo.nodes[id] ? nodeName(topo.nodes[id]) : id)).join(', ');
  const cap = sum.capture;
  const decrypted = cap.decrypt_ok + cap.decrypt_failed > 0 ? cap.decrypt_ok / (cap.decrypt_ok + cap.decrypt_failed) : null;
  const lq = sum.links.lq;
  return h('div', { class: 'diag-cards' },
    card(t('diag.card.nodes'), `${sum.nodes.online} / ${sum.nodes.total}`,
      fillTemplate(t('diag.card.nodes.sub'), { offline: sum.nodes.offline, indirect: sum.nodes.indirect_only }, (k, v) => v)),
    card(t('diag.card.routers'), `${sum.routers.count} / ${sum.routers.limit}`, t('diag.card.routers.sub'),
      h('div', { class: 'meter' }, h('div', { class: 'meter-fill', style: `width:${Math.min(100, (100 * sum.routers.count) / sum.routers.limit)}%` }))),
    card(t('diag.card.partitions'), String(sum.partitions.length),
      sum.partitions.map(p => `0x${p.id.toString(16)}`).join(', ') || null),
    card(t('diag.card.br'), String(sum.border_routers.length),
      sum.border_routers.length ? names(sum.border_routers.map(b => b.id)) : t('diag.card.br.none')),
    card(t('diag.card.links'), String(sum.links.fresh),
      fillTemplate(t('diag.card.links.sub'), { stale: sum.links.stale }, (k, v) => v),
      h('div', { class: 'lqdist' }, ...[3, 2, 1].map(q => h('span', { class: 'lqchip', title: `LQ ${q}` }, lqMeter(q), String(lq[q]))))),
    card(t('diag.card.capture'), cap.last_frame_age === null ? '–' : fmtDuration(cap.last_frame_age),
      cap.last_frame_age === null && cap.frames_last_hour === 0 ? t('diag.card.capture.none')
        : decrypted === null ? fillTemplate(t('diag.card.capture.sub.nodecrypt'), { frames: cap.frames_last_hour }, (k, v) => v)
        : fillTemplate(t('diag.card.capture.sub'), { frames: cap.frames_last_hour, pct: fmtPct(decrypted) }, (k, v) => v)),
    activeCard(sum.active),
    card(t('diag.card.since'), cap.first_frame ? ago(cap.first_frame) : '–', cap.first_frame ? absTime(cap.first_frame) : null));
}

function allFindings() {
  const out = (state.diag.summary.findings || []).map(f => ({ f, nodeId: null }));
  for (const [id, info] of Object.entries(state.diag.nodes)) {
    if (state.topo.nodes[id]) for (const f of info.findings) out.push({ f, nodeId: id });
  }
  const name = x => (x.nodeId ? nodeName(state.topo.nodes[x.nodeId]).toLowerCase() : '');
  return out.sort((a, b) => sevRank(b.f.severity) - sevRank(a.f.severity) || a.f.code.localeCompare(b.f.code) || name(a).localeCompare(name(b)));
}

// warnings and critical findings stay open; the plain notes are folded away so they do not bury the important ones
function findingList(findings) {
  if (!findings.length) return h('p', { class: 'muted' }, t('diag.findings.none'));
  const major = findings.filter(x => x.f.severity === 'warn' || x.f.severity === 'crit');
  const minor = findings.filter(x => !(x.f.severity === 'warn' || x.f.severity === 'crit'));
  return [major.map(({ f, nodeId }) => findingRow(f, nodeId)),
    minor.length ? h('details', { class: 'minor', open: major.length === 0 ? 'open' : null },
      h('summary', {}, fillTemplate(t('diag.findings.minor'), { n: minor.length }, (k, v) => v)),
      minor.map(({ f, nodeId }) => findingRow(f, nodeId))) : null];
}

const SORTS = {
  status: (n, d) => sevRank(d.status),
  name: n => nodeName(n).toLowerCase(),
  role: n => ROLES.indexOf(n.role),
  version: n => n.version ?? -1,
  frames: (n, d) => d.brief.frames_hour,
  retries: (n, d) => d.brief.retry_rate ?? -1,
  rssi: (n, d) => d.brief.rssi_avg ?? -999,
  timing: (n, d) => d.brief.adv_mean ?? d.brief.poll_mean ?? -1,
  children: (n, d) => d.brief.children,
  heard: n => n.last_heard || 0,
  findings: (n, d) => d.findings.length,
};

function diagRows() {
  const rows = Object.values(state.topo.nodes).filter(n => !n.placeholder && state.diag.nodes[n.id])
    .map(n => ({ n, d: state.diag.nodes[n.id] }))
    .filter(r => matchesQuery(r.n, state.diagFilter, searchText(r.n)));
  const { key, dir } = state.diagSort, get = SORTS[key];
  rows.sort((a, b) => {
    const x = get(a.n, a.d), y = get(b.n, b.d);
    return (x < y ? -1 : x > y ? 1 : 0) * dir || nodeName(a.n).localeCompare(nodeName(b.n));
  });
  return rows;
}

function diagTable() {
  const input = h('input', { type: 'search', placeholder: t('filter'), value: state.diagFilter, 'aria-label': t('filter') });
  input.addEventListener('input', () => {
    state.diagFilter = input.value; render();
    const fresh = document.querySelector('#view input');
    if (fresh) { fresh.focus(); fresh.setSelectionRange(fresh.value.length, fresh.value.length); }
  });
  const columns = [['status', 'diag.col.health'], ['name', 'diag.col.node'], ['role', 'col.role'], ['version', 'diag.col.version'], [null, 'diag.col.state'],
    ['frames', 'diag.col.frames'], ['retries', 'diag.col.retries'], ['rssi', 'diag.col.rssi'], ['timing', 'diag.col.timing'],
    ['children', 'diag.col.children'], ['heard', 'diag.col.heard'], ['findings', 'diag.col.findings']];
  const head = h('tr', {}, ...columns.map(([key, label]) => {
    const th = h('th', { class: key ? 'sortable' : null, 'aria-sort': key && state.diagSort.key === key ? (state.diagSort.dir > 0 ? 'ascending' : 'descending') : null },
      t(label), key && state.diagSort.key === key ? (state.diagSort.dir > 0 ? ' ▲' : ' ▼') : '');
    if (key) th.addEventListener('click', () => {
      state.diagSort = { key, dir: state.diagSort.key === key ? -state.diagSort.dir : (key === 'name' || key === 'role' ? 1 : -1) };
      render();
    });
    return th;
  }));
  const body = diagRows().map(({ n, d }) => {
    const b = d.brief;
    const timing = b.adv_mean !== null ? `${fmtDuration(b.adv_mean)} ${t('diag.adv.short')}` : b.poll_mean !== null ? `${fmtDuration(b.poll_mean)} ${t('diag.poll.short')}` : '–';
    return h('tr', { class: `row${n.online ? '' : ' offline'}`, onclick: () => openDiagNode(n.id) },
      h('td', {}, healthDot(d.status)), h('td', {}, nodeName(n), n.border_router ? [' ', abbr('BR')] : null,
        n.diag_self ? [' ', h('span', { class: 'tag', title: t('diag.self.tip') }, t('diag.self'))] : null),
      h('td', {}, roleChip(n.role)), h('td', {}, fmtThreadVersion(n.version)),
      h('td', {}, n.online_indirect ? t('online.indirect') : t(n.online ? 'online' : 'offline')),
      h('td', { class: 'num' }, String(b.frames_hour)), h('td', { class: 'num' }, fmtPct(b.retry_rate)),
      h('td', { class: 'num' }, b.rssi_avg === null ? '–' : fmtDbm(b.rssi_avg)), h('td', { class: 'num' }, timing),
      h('td', { class: 'num' }, n.role === 'router' || n.role === 'leader' ? String(b.children) : ''),
      h('td', {}, ago(n.last_heard)), h('td', { class: 'num' }, String(d.findings.length)));
  });
  return h('div', {}, h('div', { class: 'toolbar' }, input),
    h('div', { class: 'tablewrap' }, h('table', { class: 'diagtable' }, h('thead', {}, head), h('tbody', {}, body))));
}

function renderDiagOverview() {
  if (!state.diag || !state.topo) return h('div', { class: 'empty' }, t('diag.loading'));
  const findings = allFindings();
  return h('div', { class: 'diag' },
    h('div', { class: 'diag-head' }, h('h2', {}, t('view.diag')), sevChip(state.diag.summary.status),
      iconButton('download', t('diag.export.csv'), { href: '/api/export/nodes.csv', download: 'thread-tree-nodes.csv' })),
    overviewCards(state.diag.summary),
    section('diag.findings.title', findingList(findings),
      h('p', { class: 'muted small' }, t(state.diag.summary.active && state.diag.summary.active.enabled ? 'diag.note.active' : 'diag.note.passive'))),
    section('diag.nodes.title', diagTable()));
}

// ---- node detail ---------------------------------------------------------------------------------------

function kindBar(kinds) {
  const total = Object.values(kinds).reduce((a, b) => a + b, 0);
  if (!total) return null;
  const order = ['data', 'adv', 'mle', 'poll', 'cmd', 'beacon', 'ack', 'other'].filter(k => kinds[k]);
  return h('div', {},
    h('div', { class: 'kindbar' }, ...order.map(k => h('div', { class: `kind kind-${k}`, style: `flex:${kinds[k]}`, title: `${t('kind.' + k)}: ${kinds[k]}` }))),
    h('div', { class: 'kindlegend' }, ...order.map(k => h('span', {}, h('i', { class: `swatch kind-${k}` }), `${t('kind.' + k)} ${kinds[k]} (${fmtPct(kinds[k] / total)})`))));
}

const noSniffer = d => d.stats.frames === 0;  // the sniffer never received a frame from this device

function signalSection(d) {
  const r = d.stats.rssi;
  if (!r) return section('diag.sec.signal', h('p', { class: 'muted' }, t(noSniffer(d) ? 'diag.nosniffer' : 'diag.no_rssi')));
  const w24 = d.stats.last_24h;
  const labels = { lang: state.lang, title: t('diag.chart.rssi'), weak: RSSI_WEAK_DBM };
  return section('diag.sec.signal',
    h('div', { class: 'tiles' },
      tile(t('diag.t.rssi_24h'), fmtDbm(w24.rssi_avg), t('diag.t.rssi_24h.tip')), tile(t('diag.t.rssi_all'), fmtDbm(r.avg)),
      tile(t('diag.t.rssi_min'), fmtDbm(r.min)), tile(t('diag.t.rssi_max'), fmtDbm(r.max)),
      tile(t('diag.t.lqi'), d.stats.lqi ? String(Math.round(d.stats.lqi.avg)) : '–'), tile(t('diag.t.samples'), String(r.n))),
    h('h4', {}, t('diag.chart.rssi')), rssiChart(d.series, labels, RSSI_WEAK_DBM),
    h('h4', {}, t('diag.chart.hist')), histogramChart(r.hist, { title: t('diag.chart.hist'), weak: RSSI_WEAK_DBM }),
    h('p', { class: 'muted small' }, t('diag.note.sniffer')));
}

function trafficSection(d) {
  const st = d.stats, w1 = st.last_hour, w24 = st.last_24h;
  const labels = { lang: state.lang, title: t('diag.chart.activity'), frames: t('diag.frames'), retries: t('diag.retries') };
  return section('diag.sec.traffic',
    noSniffer(d) ? h('p', { class: 'muted' }, t('diag.nosniffer')) : null,
    h('div', { class: 'tiles' },
      tile(t('diag.t.frames_hour'), String(w1.frames)), tile(t('diag.t.frames_24h'), String(w24.frames)),
      tile(t('diag.t.frames_total'), String(st.frames)), tile(t('diag.t.bytes'), fmtBytes(st.bytes), t('diag.t.bytes.tip')),
      tile(t('diag.t.retry'), fmtPct(w24.retry_rate, 1), t('diag.t.retry.tip')),
      tile(t('diag.t.addressed'), String(st.addressed), t('diag.t.addressed.tip'))),
    kindBar(st.kinds),
    h('h4', {}, t('diag.chart.activity')), activityChart(d.series, labels),
    h('p', { class: 'muted small' }, t('diag.note.sniffer')));
}

function timingSection(d) {
  const adv = d.stats.adv, poll = d.stats.poll, w1 = d.stats.last_hour;
  if (!adv && !poll) return null;
  const tiles = [];
  if (adv) tiles.push(tile(t('diag.t.adv_mean'), fmtDuration(adv.mean), t('diag.t.adv.tip')),
    tile(t('diag.t.range'), `${fmtDuration(adv.min)} … ${fmtDuration(adv.max)}`), tile(t('diag.t.adv_hour'), String(w1.adv)));
  if (poll) tiles.push(tile(t('diag.t.poll_mean'), fmtDuration(poll.mean), t('diag.t.poll.tip')),
    tile(t('diag.t.range'), `${fmtDuration(poll.min)} … ${fmtDuration(poll.max)}`), tile(t('diag.t.poll_hour'), String(w1.polls)));
  return section('diag.sec.timing', h('div', { class: 'tiles' }, ...tiles));
}

const lossCell = pct => h('td', { class: `num${pct !== null && pct !== undefined && pct >= LINK_LOSS_HIGH ? ' loss-high' : ''}` }, fmtPercentValue(pct));

// rhythm of a sleepy device and its searches for a parent (sniffer)
function behaviorSection(d) {
  const b = d.behavior;
  if (!b) return null;
  const labels = { lang: state.lang, title: t('diag.chart.polls'), frames: t('kind.poll'), retries: t('diag.retries') };
  const polls = { ...d.series, frames: d.series.polls, retries: d.series.polls.map(() => 0) };
  return section('diag.sec.behavior',
    b.searching ? h('p', {}, h('span', { class: 'tag reach-indirect' }, t('diag.b.searching'))) : null,
    h('div', { class: 'tiles' },
      tile(t('diag.b.usual'), fmtDuration(b.usual), t('diag.b.usual.tip')),
      tile(t('diag.b.timeout'), fmtDuration(b.timeout), t('diag.b.timeout.tip')),
      tile(t('diag.b.last'), b.last_poll ? ago(b.last_poll) : '–'),
      tile(t('diag.b.gaps'), String(b.gaps_24h)),
      tile(t('diag.b.longest'), fmtDuration(b.longest_gap_24h)),
      tile(t('diag.b.searches'), String(b.searches_24h), t('diag.b.searches.tip'))),
    d.stats.poll ? [h('h4', {}, t('diag.chart.polls')), activityChart(polls, labels)] : null,
    h('p', { class: 'muted small' }, t('diag.note.behavior')));
}

function linksSection(d) {
  if (!d.links.length) return d.role === 'router' || d.role === 'leader'
    ? section('diag.sec.links', h('p', { class: 'muted' }, t('diag.links.none'))) : null;
  const measured = d.links.some(l => l.metrics);  // columns of the routers' own measurements only if there are any
  const rows = d.links.map(l => {
    const nb = l.neighbor, m = l.metrics;
    const who = nb && !nb.placeholder ? nodeLinkTo(nb.id, nb.name || (nb.ext ? '…' + fmtMac(nb.ext).slice(-11) : nb.rloc16)) :
      h('span', { class: 'muted' }, `${t('placeholder.router')} ${routerLabel(l.neighbor_router_id)}`);
    return h('tr', { class: l.stale ? 'offline' : null }, h('td', {}, who),
      h('td', {}, t(l.reported_by === 'self' ? 'diag.link.self' : 'diag.link.neighbor_rep')),
      h('td', {}, h('span', { class: 'lqpair' }, lqMeter(l.lq_in), ` ${l.lq_in} / `, lqMeter(l.lq_out), ` ${l.lq_out}`)),
      h('td', { class: 'num' }, fmtCost(l.cost)), h('td', {}, fmtDuration(l.age), l.stale ? [' ', h('span', { class: 'tag' }, t('link.stale'))] : null),
      measured ? [h('td', { class: 'num' }, m ? fmtDbm(m.rss_ave) : '–'), h('td', { class: 'num' }, m ? fmtDb(m.margin) : '–'),
        lossCell(m ? m.frame_err : null), lossCell(m ? m.msg_err : null), h('td', { class: 'num' }, m ? fmtDuration(m.conn_time) : '–')] : null);
  });
  const heads = ['diag.link.neighbor', 'diag.link.reported', 'diag.link.quality', 'diag.link.cost', 'diag.link.age',
    ...(measured ? ['diag.link.signal', 'diag.link.margin', 'diag.link.frames', 'diag.link.msgs', 'diag.link.conn'] : [])];
  return section('diag.sec.links', h('div', { class: 'tablewrap' }, h('table', {},
    h('thead', {}, h('tr', {}, ...heads.map(k => h('th', { title: k === 'diag.link.margin' ? t('diag.l.margin.tip') : null }, t(k))))),
    h('tbody', {}, rows))), measured ? h('p', { class: 'muted small' }, t('diag.link.note')) : null);
}

// the parent router's measurements of an end device (active diagnostics)
function parentLinkSection(d) {
  const k = d.link;
  if (!k) return null;
  const off = v => (v ? fmtDuration(v) : t('diag.l.off'));
  const last = k.rss_last === null || k.rss_last === undefined ? '' : ` (${t('diag.l.last')}: ${fmtDbm(k.rss_last)})`;
  return section('diag.sec.parentlink',
    h('div', { class: 'tiles' },
      tile([abbr('RSS'), ' ', t('diag.l.rss')], fmtDbm(k.rss_ave), t('diag.l.rss.tip') + last),
      tile(t('diag.l.margin'), fmtDb(k.margin), t('diag.l.margin.tip')),
      tile(t('diag.l.frame'), fmtPercentValue(k.frame_err), t('diag.l.frame.tip')),
      tile(t('diag.l.msg'), fmtPercentValue(k.msg_err), t('diag.l.msg.tip')),
      tile(t('diag.l.age'), fmtDuration(k.age), t('diag.l.age.tip')),
      tile(t('diag.l.timeout'), fmtDuration(k.timeout)),
      tile(t('diag.l.conn'), fmtDuration(k.conn_time)),
      tile(t('diag.l.queued'), k.queued === null || k.queued === undefined ? '–' : String(k.queued), t('diag.l.queued.tip')),
      tile(t('diag.l.supervision'), off(k.supervision), t('diag.l.supervision.tip'))),
    h('p', { class: 'muted small' }, fillTemplate(t('diag.note.parentlink'), { ago: ago(k.ts) }, (key, v) => v)));
}

function parentSection(d) {
  if (!d.parent) return null;
  const p = d.parent;
  return section('diag.sec.parent', p.placeholder || !p.id
    ? h('p', { class: 'muted' }, `${t('placeholder.router')} ${routerLabel(p.router_id)}`)
    : h('p', {}, nodeLinkTo(p.id, p.name || (p.ext ? '…' + fmtMac(p.ext).slice(-11) : p.rloc16)), ' ', roleChip(p.role), ' ',
      h('span', { class: 'muted' }, t(p.online ? 'online' : 'offline'))));
}

function childrenSection(d) {
  if (!d.children.length) return null;
  const measured = d.children.some(c => c.link);  // the parent's own measurements, if the active diagnostics have them
  const rows = d.children.map(c => {
    const k = c.link;
    return h('tr', { class: c.online ? null : 'offline' },
      h('td', {}, nodeLinkTo(c.id, c.name || (c.ext ? '…' + fmtMac(c.ext).slice(-11) : c.rloc16)), c.diag_self ? [' ', h('span', { class: 'tag' }, t('diag.self'))] : null),
      h('td', {}, roleChip(c.role)), h('td', { class: 'mono' }, c.rloc16 || '–'), h('td', {}, t(c.online ? 'online' : 'offline')),
      measured ? [h('td', {}, fmtThreadVersion(c.version)), h('td', { class: 'num' }, k ? fmtDbm(k.rss_ave) : '–'),
        lossCell(k ? k.frame_err : null), h('td', { class: 'num' }, k ? fmtDuration(k.age) : '–')] : null);
  });
  const head = measured ? h('thead', {}, h('tr', {}, ...['diag.children.device', 'col.role', 'col.rloc16', 'd.state', 'diag.col.version', 'diag.link.signal', 'diag.link.frames', 'diag.l.age'].map(k => h('th', {}, t(k))))) : null;
  return section('diag.sec.children', h('div', { class: 'tablewrap' }, h('table', {}, head, h('tbody', {}, rows))),
    measured ? h('p', { class: 'muted small' }, t('diag.children.note')) : null);
}

function historySection(d) {
  if (!d.events.length) return section('diag.sec.history', h('p', { class: 'muted' }, t('diag.history.none')));
  return section('diag.sec.history', h('ul', { class: 'timeline' }, ...d.events.map(ev =>
    h('li', { class: `ev ev-${ev.kind}` }, h('span', { class: 'ev-time', title: absTime(ev.ts) }, absTime(ev.ts)), h('span', {}, eventText(ev))))));
}

function renderNodeDiag() {
  const back = iconButton('back', t('diag.back'), { onclick: closeDiagNode });
  const d = state.diagDetail;
  if (!d || d.id !== state.diagNode) return h('div', { class: 'diag' }, h('div', { class: 'diag-head' }, back), h('div', { class: 'empty' }, t('diag.loading')));
  const n = state.topo && state.topo.nodes[d.id];
  const title = d.name || (d.ext ? '…' + fmtMac(d.ext).slice(-11) : d.rloc16 || d.id);
  const facts = h('dl', { class: 'facts' },
    h('dt', {}, abbr('MAC', t('d.mac'))), h('dd', { class: 'mono' }, d.ext ? fmtMac(d.ext) : '–'),
    h('dt', {}, abbr('RLOC16')), h('dd', { class: 'mono' }, d.rloc16 || '–'),
    h('dt', {}, t('col.partition')), h('dd', {}, d.partition_id === null ? '–' : `0x${d.partition_id.toString(16)}`),
    h('dt', {}, t('d.state')), h('dd', {}, d.online_indirect ? t('online.indirect') : t(d.online ? 'online' : 'offline')),
    h('dt', {}, t('d.first')), h('dd', {}, ago(d.first_seen)), h('dt', {}, t('d.last')), h('dd', {}, ago(d.last_seen)),
    h('dt', {}, t('diag.t.heard')), h('dd', {}, d.heard ? ago(d.last_heard) : t('reach.indirect')),
    d.version !== null && d.version !== undefined ? [h('dt', {}, t('d.version')), h('dd', {}, fmtThreadVersion(d.version))] : [],
    d.vendor ? [h('dt', {}, t('d.vendor')), h('dd', {}, [d.vendor.name, d.vendor.model].filter(Boolean).join(' · ') || '–', d.vendor.sw ? ` (${d.vendor.sw})` : '')] : [],
    d.vendor && d.vendor.stack ? [h('dt', {}, t('d.stack')), h('dd', { class: 'mono' }, d.vendor.stack)] : [],
    d.last_diag ? [h('dt', {}, t('d.diag')), h('dd', {}, ago(d.last_diag))] : []);
  return h('div', { class: 'diag' },
    h('div', { class: 'diag-head' }, back, h('h2', {}, title), roleChip(d.role), d.border_router ? abbr('BR') : null,
      d.diag_self ? h('span', { class: 'tag', title: t('diag.self.tip') }, t('diag.self')) : null, sevChip(d.status),
      n ? iconButton('locate', t('diag.show_in_tree'), { onclick: () => { state.view = 'tree'; state.selected = d.id; render(); } }) : null,
      iconButton('json', t('diag.export.json'), { href: `/api/nodes/${encodeURIComponent(d.id)}/diagnostics`, download: `thread-tree-${d.id}.json` })),
    facts,
    d.findings.length ? section('diag.findings.title', d.findings.map(f => findingRow(f, null))) : null,
    behaviorSection(d), signalSection(d), trafficSection(d), timingSection(d), linksSection(d), parentSection(d), parentLinkSection(d), childrenSection(d),
    historySection(d),
    section('diag.sec.addresses', d.addresses.length ? addressList({ addresses: d.addresses }, false) : h('p', { class: 'muted' }, '–')));
}

function renderDiagnose() {
  return state.diagNode ? renderNodeDiag() : renderDiagOverview();
}
