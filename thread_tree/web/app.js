'use strict';

const ROLES = ['leader', 'router', 'fed', 'med', 'sed', 'child', 'unknown'];
const TYPES = ['rloc', 'aloc', 'ml-eid', 'omr', 'link-local'];
const VIEWS = ['tree', 'mesh', 'table', 'diag', 'tests', 'log'];
const state = { notice: null, lang: 'en', dicts: {}, config: null, topo: null, status: null, view: 'tree', partition: null, selected: null, filter: '',
  diag: null, diagNode: null, diagDetail: null, diagFilter: '', diagSort: { key: 'status', dir: -1 } };

// ---- helpers ---------------------------------------------------------------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  el.append(...kids.flat(Infinity).filter(k => k != null));
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v);
  }
  el.append(...kids.flat(Infinity).filter(k => k != null));
  return el;
}
// replaceChildren() stringifies arrays and null: flatten and drop empty entries first
const fill = (el, ...kids) => el.replaceChildren(...kids.flat(Infinity).filter(k => k != null && k !== false));
const dict = () => state.dicts[state.lang];
const t = key => dict()[key] ?? state.dicts.en[key] ?? key;
function abbr(code, text) {
  const entry = dict().abbr[code];
  return entry ? h('abbr', { title: `${entry[0]} — ${entry[1]}` }, text ?? code) : document.createTextNode(text ?? code);
}
function typeLabel(type) {
  switch (type) {
    case 'rloc': return abbr('RLOC');
    case 'aloc': return abbr('ALOC');
    case 'ml-eid': return abbr('ML-EID');
    case 'omr': return h('span', {}, abbr('OMR'), '/', abbr('GUA'));
    default: return document.createTextNode(t('type.' + type));
  }
}
// MAC address (IEEE 802.15.4 extended address / EUI-64) as aa:bb:cc:dd:ee:ff:00:11, like Wireshark
const fmtMac = ext => ext.match(/../g).join(':');
function macCell(n) {
  if (!n.ext) return h('span', { class: 'muted', title: t('mac.unknown') }, '—');
  return h('span', { class: 'addr' }, h('span', { class: 'mono' }, fmtMac(n.ext)), copyButton(fmtMac(n.ext)));
}
function roleLabel(role) { return t('role.' + role); }
function nodeName(n) {
  if (n.placeholder) return t(n.role === 'router' ? 'placeholder.router' : n.role === 'detached' ? 'placeholder.detached' : 'placeholder.' + n.role);
  if (n.name) return n.name;
  return n.ext ? '…' + fmtMac(n.ext).slice(-11) : (n.rloc16 || n.id);
}
const hwId = n => (n.ext ? '…' + fmtMac(n.ext).slice(-11) : (n.rloc16 || n.id));  // identity next to a given name
function ago(ts) {
  if (!ts) return t('never');
  const sec = Math.round(ts - Date.now() / 1000);
  const rtf = new Intl.RelativeTimeFormat(state.lang, { numeric: 'auto' });
  const a = Math.abs(sec);
  if (a < 60) return rtf.format(sec, 'second');
  if (a < 3600) return rtf.format(Math.round(sec / 60), 'minute');
  if (a < 86400) return rtf.format(Math.round(sec / 3600), 'hour');
  return rtf.format(Math.round(sec / 86400), 'day');
}
function copyButton(text) {
  const b = h('button', { class: 'copy', type: 'button', title: t('copy') }, '⧉');
  b.addEventListener('click', async ev => {
    ev.stopPropagation();
    try { await navigator.clipboard.writeText(text); b.textContent = '✓'; b.title = t('copied'); setTimeout(() => { b.textContent = '⧉'; }, 1200); } catch { /* clipboard unavailable */ }
  });
  return b;
}
function roleChip(role) {
  return h('span', { class: 'chip', style: `background:var(--${ROLES.includes(role) ? role : 'unknown'})` }, roleLabel(role));
}
const partitionData = () => state.topo?.partitions.find(p => p.id === state.partition);

// ---- tree view -------------------------------------------------------------
const CARD_W = 200, CARD_H = 40, COL_W = 250, ROW_H = 54, PAD = 10;

function layout(root) {
  let leaf = 0;
  const pos = new Map();
  (function go(n, depth) {
    let y;
    if (!n.children.length) y = leaf++;
    else { const ys = n.children.map(c => go(c, depth + 1)); y = (ys[0] + ys[ys.length - 1]) / 2; }
    pos.set(n.id, { x: depth * COL_W + PAD, y: y * ROW_H + PAD });
    return y;
  })(root, 0);
  return pos;
}
function glyph(n, cx, cy, r) {
  const cls = `glyph role-${n.role}`;
  return [s('circle', { cx, cy, r, class: cls }), s('text', { x: cx, y: cy + 4, class: 'glyph-txt' }, t('role.short.' + n.role))];
}
function nodeCard(n, x, y, onclick) {
  const g = s('g', { class: `node${n.online || n.placeholder ? '' : ' offline'}${state.selected === n.id ? ' selected' : ''}${n.placeholder ? ' placeholder' : ''}`, transform: `translate(${x},${y})`, onclick });
  g.append(s('title', {}, [nodeName(n), n.name ? hwId(n) : null, n.rloc16, roleLabel(n.role)].filter(Boolean).join(' · ')));
  g.append(s('rect', { class: 'card', width: CARD_W, height: CARD_H, rx: 8 }));
  g.append(...glyph(n, 20, CARD_H / 2, 12));
  g.append(s('text', { x: 40, y: 16 }, nodeName(n)));
  g.append(s('text', { x: 40, y: 31, class: 'sub' }, [n.rloc16, n.placeholder ? '' : roleLabel(n.role)].filter(Boolean).join(' · ')));
  if (!n.placeholder && !n.heard) {  // known only from other nodes' traffic
    g.append(s('circle', { cx: CARD_W - 12, cy: CARD_H - 11, r: 5, class: 'indirect' }, s('title', {}, t('reach.indirect'))));
  }
  if (n.health === 'warn' || n.health === 'crit') {  // something to look at: see the Diagnosis view
    g.append(s('circle', { cx: 6, cy: 6, r: 5, class: `dot-svg dot-${n.health}` }, s('title', {}, t('sev.' + n.health))));
  }
  if (n.border_router) {
    g.append(s('rect', { x: CARD_W - 30, y: 5, width: 24, height: 15, rx: 4, class: 'badge-br' }));
    g.append(s('text', { x: CARD_W - 18, y: 16, class: 'badge-txt', 'text-anchor': 'middle' }, 'BR'));
  }
  return g;
}
function renderTree(p) {
  const pos = layout(p.root);
  const width = Math.max(...[...pos.values()].map(v => v.x)) + CARD_W + PAD * 2;
  const height = Math.max(...[...pos.values()].map(v => v.y)) + CARD_H + PAD * 2;
  const svg = s('svg', { width, height, role: 'img', 'aria-label': t('view.tree') });
  const edges = s('g', {}), nodes = s('g', {});
  (function go(n) {
    const a = pos.get(n.id);
    for (const c of n.children) {
      const b = pos.get(c.id);
      const x1 = a.x + CARD_W, y1 = a.y + CARD_H / 2, x2 = b.x, y2 = b.y + CARD_H / 2, mx = (x1 + x2) / 2;
      const kind = c.edge.kind;
      const w = kind === 'link' ? 1 + (c.edge.lq || 1) : 1.5;
      const path = s('path', { class: `edge ${kind}`, d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`, 'stroke-width': w });
      if (kind === 'unknown') path.append(s('title', {}, t('unknown-link')));
      edges.append(path);
      go(c);
    }
    nodes.append(nodeCard(state.topo.nodes[n.id], a.x, a.y, () => select(n.id)));
  })(p.root);
  svg.append(edges, nodes);
  return svg;
}

// ---- mesh view -------------------------------------------------------------
const MESH_LOSS_HIGH = 25;  // percent of frames lost: same threshold as the server's "lossy link" finding
function meshTip(ls) {
  const name = id => (state.topo.nodes[id] ? nodeName(state.topo.nodes[id]) : '?');
  return ls.map(l => {
    const m = l.metrics;
    return `${name(l.from)} → ${name(l.to)}: ${t('link.in')} ${l.lq_in} / ${t('link.out')} ${l.lq_out}`
      + (m ? ` · ${fmtDbm(m.rss_ave)} · ${fmtPercentValue(m.frame_err)} ${t('d.lost')}` : '') + (l.stale ? ` — ${t('link.stale')}` : '');
  }).join('\n');
}
function renderMesh(p) {
  const routers = Object.values(state.topo.nodes).filter(n => n.partition_id === p.id && ['leader', 'router'].includes(n.role))
    .sort((a, b) => (a.role === 'leader' ? -1 : b.role === 'leader' ? 1 : (a.rloc16 || '').localeCompare(b.rloc16 || '')));
  const count = Math.max(1, routers.length);
  // radius so that neighbouring cards never overlap: the chord between two neighbours must exceed a card plus a gap
  const R = count < 3 ? 140 : Math.max(140, Math.ceil((CARD_W + 50) / (2 * Math.sin(Math.PI / count))));
  const W = 2 * R + CARD_W + 2 * PAD, H = 2 * R + CARD_H + 2 * PAD, cx = W / 2, cy = H / 2;
  const svg = s('svg', { width: W, height: H, role: 'img', 'aria-label': t('view.mesh') });
  const at = new Map(routers.map((n, i) => {
    const a = (2 * Math.PI * i) / count - Math.PI / 2;
    return [n.id, { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) }];
  }));
  const pairs = new Map();  // one line per pair of routers, both directions together
  for (const l of state.topo.links) {
    if (!at.has(l.from) || !at.has(l.to)) continue;
    const key = [l.from, l.to].sort().join('|');
    if (!pairs.has(key)) pairs.set(key, []);
    pairs.get(key).push(l);
  }
  const lines = s('g', {}), badges = s('g', {});
  for (const ls of pairs.values()) {
    const a = at.get(ls[0].from), b = at.get(ls[0].to);
    const lq = Math.min(...ls.flatMap(l => [l.lq_in, l.lq_out]));
    const lost = Math.max(0, ...ls.map(l => (l.metrics && l.metrics.frame_err) || 0));
    const cls = `mesh-link lq-${lq}${ls.every(l => l.stale) ? ' stale' : ''}${lost >= MESH_LOSS_HIGH ? ' lossy' : ''}`;
    const tip = meshTip(ls);
    const line = s('line', { class: cls, x1: a.x, y1: a.y, x2: b.x, y2: b.y });
    line.append(s('title', {}, tip));
    lines.append(line);
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;  // quality in the middle of the line, red ring if frames are lost
    const badge = s('g', { class: `mesh-badge lq-${lq}${lost >= MESH_LOSS_HIGH ? ' lossy' : ''}`, transform: `translate(${mx},${my})` },
      s('circle', { r: 11 }), s('text', { y: 4, 'text-anchor': 'middle' }, String(lq)));
    badge.append(s('title', {}, tip));
    badges.append(badge);
  }
  svg.append(lines);
  for (const n of routers) {
    const a = at.get(n.id);
    svg.append(nodeCard(n, a.x - CARD_W / 2, a.y - CARD_H / 2, () => select(n.id)));
  }
  svg.append(badges);  // above the cards: a line may pass under one
  return svg;
}

// ---- table view ------------------------------------------------------------
function searchText(n) {
  return [n.name, n.role, roleLabel(n.role), n.rloc16, n.ext, n.ext ? fmtMac(n.ext) : '', n.border_router ? 'br' : '', ...n.addresses.map(a => a.addr)].join(' ').toLowerCase();
}
function reachLabel(n) {
  return h('span', { class: `tag reach-${n.heard ? 'direct' : 'indirect'}`, title: t(n.heard ? 'reach.direct.tip' : 'reach.indirect.tip') },
    t(n.heard ? 'reach.direct' : 'reach.indirect'));
}
function addressList(n, compact) {
  return n.addresses.map(a => h('div', { class: 'addr' },
    h('span', { class: 'mono' }, a.addr), h('span', { class: 'tag' }, typeLabel(a.type)),
    compact ? null : h('span', { class: 'tag' }, t('d.source.' + a.source)), copyButton(a.addr)));
}
function renderTable(p) {
  const rows = Object.values(state.topo.nodes).filter(n => !n.placeholder && n.partition_id === p.id)
    .filter(n => matchesQuery(n, state.filter, searchText(n)))
    .sort((a, b) => (a.rloc16 || '~').localeCompare(b.rloc16 || '~'));
  const input = h('input', { type: 'search', placeholder: t('filter'), value: state.filter, 'aria-label': t('filter') });
  input.addEventListener('input', () => {
    state.filter = input.value; render();
    const fresh = document.querySelector('#view input');  // render() replaced the element
    if (fresh) { fresh.focus(); fresh.setSelectionRange(fresh.value.length, fresh.value.length); }
  });
  const head = h('tr', {}, ...['col.name', 'col.role', 'col.rloc16', 'col.mac', 'col.reach', 'col.addresses', 'col.seen'].map(k =>
    h('th', {}, k === 'col.mac' ? [abbr('MAC'), ' / ', abbr('EUI-64')] : k === 'col.rloc16' ? abbr('RLOC16') : t(k))));
  const body = rows.map(n => h('tr', { class: `row${n.online ? '' : ' offline'}${state.selected === n.id ? ' selected' : ''}`, onclick: () => select(n.id) },
    h('td', {}, n.name || '—'), h('td', {}, roleChip(n.role), ' ', n.border_router ? abbr('BR') : null), h('td', { class: 'mono' }, n.rloc16 || '—'),
    h('td', {}, macCell(n)), h('td', {}, reachLabel(n)), h('td', {}, addressList(n, true)), h('td', {}, ago(n.last_seen))));
  return h('div', {}, h('div', { class: 'toolbar' }, input), h('table', {}, h('thead', {}, head), h('tbody', {}, body)));
}

// ---- drawer ----------------------------------------------------------------
function findInTree(n, id) {
  if (n.id === id) return n;
  for (const c of n.children) { const r = findInTree(c, id); if (r) return r; }
  return null;
}
async function putName(id, name) {
  const res = await fetch(`/api/nodes/${encodeURIComponent(id)}/name`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.status);
}
function nameEditor(n) {
  if (n.placeholder) return null;
  if (state.config && state.config.can_name === false) return h('p', { class: 'muted' }, t('d.name.locked'));
  const msg = h('span', { class: 'msg error', role: 'status' });
  const input = h('input', { type: 'text', maxlength: '64', value: n.name || '', placeholder: t('d.name.placeholder'), 'aria-label': t('d.name'), class: 'wide' });
  const apply = async name => {
    try { await putName(n.id, name); input.blur(); await poll(); } catch (err) { msg.textContent = `${t('set.error')}: ${err.message}`; }
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') apply(input.value); });
  const save = h('button', { type: 'button', onclick: () => apply(input.value) }, t('d.name.save'));
  const clear = n.name ? h('button', { type: 'button', onclick: () => apply('') }, t('d.name.remove')) : null;
  return h('div', { class: 'name-editor' }, h('label', {}, t('d.name')), h('div', { class: 'toolbar' }, input, save, clear),
    n.ext ? null : h('p', { class: 'muted' }, t('d.name.noext')),
    n.name && n.identity_via_rloc ? h('p', { class: 'muted' },
      t('d.name.viarloc').replace('{since}', ago(n.mac_confirmed)).replace('{rloc}', n.rloc16)) : null,
    msg);
}
// The other end of a router link; a router that was never heard has no node entry.
function neighborLabel(n, l, nodeLink) {
  const otherId = l.from === n.id ? l.to : l.from;
  if (otherId && state.topo.nodes[otherId]) return nodeLink(otherId);
  const rid = l.from === n.id ? l.to_router_id : l.from_router_id;
  return h('span', { class: 'muted' }, `${t('placeholder.router')} 0x${(rid << 10).toString(16).padStart(4, '0')}`);
}
function renderDrawer() {
  const d = document.getElementById('drawer');
  const n = state.selected && state.topo?.nodes[state.selected];
  d.hidden = !n;
  if (!n) return;
  const p = partitionData();
  const tn = p && findInTree(p.root, n.id);
  const dd = (label, ...v) => [h('dt', {}, label), h('dd', {}, ...v)];
  const nodeLink = id => { const m = state.topo.nodes[id]; return h('a', { href: '#', onclick: e => { e.preventDefault(); select(id); } }, nodeName(m) + (m.rloc16 ? ` (${m.rloc16})` : '')); };
  const links = state.topo.links.filter(l => l.from === n.id || l.to === n.id);
  const mode = n.ftd == null ? '—' : [n.ftd ? 'FTD' : 'MTD', n.rx_on_idle ? 'rx-on-idle' : 'rx-off-idle'];
  fill(d,
    h('h2', {}, nodeName(n), roleChip(n.role), n.border_router ? abbr('BR') : null,
      n.diag_self ? h('span', { class: 'tag', title: t('diag.self.tip') }, t('diag.self')) : null,
      h('button', { type: 'button', class: 'ibtn icon-only', style: 'margin-left:auto', onclick: () => select(null), 'aria-label': t('legend.close'), title: t('legend.close') }, icon('close'))),
    nameEditor(n),
    n.placeholder ? null : h('p', {}, iconButton('diag', t('diag.open'), { onclick: () => openDiagNode(n.id) })),
    h('dl', {},
      n.border_router ? dd(abbr('BR'), t('d.br').replace('{since}', ago(n.br_seen))) : [],
      dd(t('d.state'), n.online_indirect ? h('span', { title: t('online.indirect.tip') }, t('online.indirect')) : t(n.online ? 'online' : 'offline')),
      n.name ? dd(t('d.hwid'), h('span', { class: 'mono' }, hwId(n))) : [],
      dd(h('span', {}, abbr('MAC', t('d.mac')), ' / ', abbr('EUI-64')), macCell(n)),
      dd(abbr('RLOC16'), h('span', { class: 'mono' }, n.rloc16 || '—')),
      dd(t('d.mode'), Array.isArray(mode) ? [abbr(mode[0]), ' · ' + mode[1]] : mode),
      n.version != null ? dd(t('d.version'), fmtThreadVersion(n.version)) : [],
      n.vendor ? dd(t('d.vendor'), [n.vendor.name, n.vendor.model].filter(Boolean).join(' · ') + (n.vendor.sw ? ` (${n.vendor.sw})` : '')) : [],
      dd(t('col.partition'), '0x' + Number(n.partition_id).toString(16)),
      n.parent ? dd(t('d.parent'), nodeLink(n.parent)) : [],
      dd(t('d.reach'), reachLabel(n), n.heard ? ` (${ago(n.last_heard)})` : ''),
      dd(t('d.first'), ago(n.first_seen)), dd(t('d.last'), ago(n.last_seen)),
      dd(h('span', { title: t('d.addressed.tip') }, t('d.addressed')), ago(n.last_addressed))),
    tn && tn.children.length ? [h('h3', {}, t('d.children')), h('div', {}, tn.children.map(c => h('div', {}, nodeLink(c.id))))] : [],
    links.length ? [h('h3', {}, t('d.neighbors')), ...links.map(l => h('div', {}, neighborLabel(n, l, nodeLink),
      ` — ${t('link.in')} ${l.lq_in} / ${t('link.out')} ${l.lq_out} / ${t('link.cost')} ${fmtCost(l.cost)}`,
      l.stale ? h('span', { class: 'tag' }, t('link.stale')) : null))] : [],
    h('h3', {}, t('d.addresses')), ...(n.addresses.length ? addressList(n, false) : [h('div', { class: 'muted' }, '—')]));
}

// ---- legend ----------------------------------------------------------------
function renderLegend() {
  const dlg = document.getElementById('legend');
  const grid = (...rows) => h('div', { class: 'legend-grid' }, rows.flat());
  dlg.replaceChildren(
    h('h2', {}, t('legend')),
    h('h3', {}, t('legend.roles')),
    grid(ROLES.filter(r => r !== 'unknown').map(r => [roleChip(r), h('span', {}, ...(r === 'fed' ? [abbr('FED'), ' / REED'] : r === 'med' ? [abbr('MED')] : r === 'sed' ? [abbr('SED')] : [])) ]),
      [h('span', { class: 'chip', style: 'background:var(--br)' }, 'BR'), h('span', {}, abbr('BR'), ' — ', t('legend.br'))],
      [h('span', {}, '◌'), h('span', {}, t('legend.offline'))],
      [h('span', { class: 'tag reach-indirect' }, t('reach.indirect')), h('span', {}, t('legend.indirect'))],
      [h('span', { class: 'tag reach-direct' }, t('reach.direct')), h('span', {}, t('legend.direct'))],
      [h('span', { class: 'tag' }, t('online.indirect')), h('span', {}, t('online.indirect.tip'))],
      [h('span', { class: 'dot dot-warn' }), h('span', {}, t('legend.health'))],
      [h('span', { class: 'tag' }, t('diag.self')), h('span', {}, t('diag.self.tip'))]),
    h('h3', {}, t('legend.edges')),
    grid([h('span', { class: 'chip', style: 'background:var(--router)' }, '━'), t('legend.edge.link')],
      [h('span', { class: 'chip', style: 'background:var(--line);color:var(--text)' }, '─'), t('legend.edge.child')],
      [h('span', { class: 'chip', style: 'background:var(--muted)' }, '┄'), t('legend.edge.unknown')],
      [h('span', { class: 'mesh-badge lq-3' }, '3'), t('legend.mesh.lq')],
      [h('span', { class: 'mesh-badge lq-1 lossy' }, '1'), t('legend.mesh.loss')]),
    h('h3', {}, t('legend.types')),
    grid(TYPES.map(ty => [h('span', { class: 'tag' }, typeLabel(ty)), abbrDesc(ty)])),
    h('h3', {}, t('legend.sources')),
    grid([h('span', { class: 'tag' }, t('d.source.derived')), t('legend.source.derived')], [h('span', { class: 'tag' }, t('d.source.observed')), t('legend.source.observed')]),
    h('h3', {}, t('legend.abbr')),
    grid(Object.entries(dict().abbr).map(([k, [name, desc]]) => [h('strong', {}, k), h('span', {}, `${name}. ${desc}`)])),
    h('p', {}, h('button', { type: 'button', onclick: () => dlg.close() }, t('legend.close'))));
}
function abbrDesc(type) {
  const map = { rloc: 'RLOC', aloc: 'ALOC', 'ml-eid': 'ML-EID', omr: 'OMR' };
  if (type === 'link-local') return dict()['type.link-local'] + ' (fe80::/10)';
  const e = dict().abbr[map[type]];
  return `${e[0]}. ${e[1]}`;
}

// ---- rebuild the tree ------------------------------------------------------
let noticeTimer = null;
function notify(text, error = false) {
  state.notice = { text, error };
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { state.notice = null; render(); }, 12000);
  render();
}
async function rebuildTree() {
  if (!confirm(t('rebuild.confirm'))) return;
  try {
    const res = await fetch('/api/topology/reset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.status);
    state.selected = null;
    await poll();
    notify(t('rebuild.done').replace('{kept}', data.names_kept).replace('{dropped}', data.names_dropped));
  } catch (err) { notify(`${t('set.error')}: ${err.message}`, true); }
}

// ---- settings (Thread dataset) ----------------------------------------------
async function loadConfig() {
  try { state.config = await fetch('/api/config').then(r => r.json()); } catch { /* keep old */ }
}
async function openSettings() {
  await loadConfig();
  renderSettings();
  document.getElementById('settings').showModal();
}
function insecureConnection() {  // the key would cross the network in clear text
  return location.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
}
function renderSettings(message) {
  const dlg = document.getElementById('settings');
  const cfg = state.config;
  if (!cfg) return;
  const ds = cfg.dataset;
  const info = ds ? h('dl', { class: 'info' },
    ...[['set.name', ds.network_name], ['set.channel', ds.channel], [null, ds.pan_id, 'PAN'], ['set.extpan', ds.ext_pan_id],
        ['set.prefix', ds.mesh_local_prefix], ['set.key', ds.has_key ? t('set.key.present') : t('set.key.missing')],
        ['set.origin', t('set.origin.' + ds.origin)]]
      .map(([k, v, a]) => [h('dt', {}, a ? abbr(a) : t(k)), h('dd', { class: 'mono' }, v == null ? '—' : String(v))])
  ) : h('p', { class: 'muted' }, t('set.none'));
  const msg = h('p', { class: `msg${message?.error ? ' error' : ''}`, role: 'status' }, message?.text || '');
  let form;
  if (!cfg.editable) {
    form = h('p', { class: 'msg' }, t('set.locked.' + (cfg.locked_reason || 'cli')));
  } else {
    const input = h('input', { type: 'password', id: 'dataset-input', autocomplete: 'off', spellcheck: 'false',
      placeholder: '0e08000000000001…', 'aria-label': t('set.dataset'), class: 'mono wide' });
    const show = h('input', { type: 'checkbox', id: 'dataset-show' });
    show.addEventListener('change', () => { input.type = show.checked ? 'text' : 'password'; });
    const save = h('button', { type: 'button' }, t('set.save'));
    save.addEventListener('click', async () => {
      const value = input.value.trim();
      if (!value) return;
      save.disabled = true;
      try {
        const res = await fetch('/api/config/dataset', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ dataset: value }) });
        const data = await res.json();
        if (!res.ok) { renderSettings({ error: true, text: `${t('set.error')}: ${data.error || res.status}` }); return; }
        state.config = data;
        renderSettings({ text: t('set.saved') });  // rebuilds the form: the key is no longer in the DOM
        poll();
      } catch { renderSettings({ error: true, text: t('set.error') }); }
    });
    const remove = ds && ds.origin === 'ui' ? h('button', { type: 'button' }, t('set.remove')) : null;
    if (remove) remove.addEventListener('click', async () => {
      if (!confirm(t('set.confirm.remove'))) return;
      try {
        const res = await fetch('/api/config/dataset', { method: 'DELETE' });
        const data = await res.json();
        if (!res.ok) { renderSettings({ error: true, text: `${t('set.error')}: ${data.error || res.status}` }); return; }
        state.config = data;
        renderSettings({ text: t('set.removed') });
        poll();
      } catch { renderSettings({ error: true, text: t('set.error') }); }
    });
    form = h('div', {},
      h('label', { for: 'dataset-input' }, t('set.dataset')), h('div', { class: 'field' }, input),
      h('label', { class: 'inline' }, show, ' ', t('set.show')),
      h('p', { class: 'muted' }, t('set.help')), h('p', { class: 'muted' }, t('set.note')),
      insecureConnection() ? h('p', { class: 'msg error' }, t('set.insecure')) : null,
      h('div', { class: 'toolbar' }, save, remove));
  }
  dlg.replaceChildren(h('h2', {}, t('settings')), h('h3', {}, t('set.current')), info, form, msg,
    h('p', {}, h('button', { type: 'button', onclick: () => dlg.close() }, t('legend.close'))));
}

// ---- main ------------------------------------------------------------------
function select(id) { state.selected = id; render(); }
function render() {
  document.documentElement.lang = state.lang;
  document.getElementById('title').textContent = t('title');
  document.title = t('title');
  const label = (id, name, text, tip) => {
    const el = document.getElementById(id);
    fill(el, icon(name), h('span', {}, text));
    el.className = 'ibtn';
    el.title = tip || text;
    return el;
  };
  label('legend-btn', 'legend', t('legend'));
  label('settings-btn', 'settings', t('settings'));
  label('rebuild-btn', 'rebuild', t('rebuild'), t('rebuild.tip')).disabled = state.config?.can_name === false;  // same rule as naming
  const db = document.getElementById('diag-btn');  // a switch, always reachable, also with an empty tree
  const on = !state.status?.diagnostics_paused;
  db.hidden = !state.status?.diagnostics;
  db.setAttribute('role', 'switch');
  db.setAttribute('aria-checked', String(on));
  db.className = `switch${on ? ' on' : ''}`;
  db.title = t('header.diag.tip');
  db.disabled = state.config?.can_name === false;
  fill(db, icon('antenna'), h('span', {}, t('header.diag')), h('span', { class: 'track' }, h('span', { class: 'knob' })),
    h('span', { class: 'state' }, t(on ? 'header.diag.state_on' : 'header.diag.state_off')));
  const views = document.getElementById('views');
  const VIEW_ICONS = { tree: 'tree', mesh: 'mesh', table: 'table', diag: 'diag', tests: 'tests', log: 'log' };
  views.replaceChildren(...VIEWS.map(v => h('button', { type: 'button', role: 'tab', class: 'ibtn', 'aria-selected': String(v === state.view),
    onclick: () => { state.view = v; render(); if (['diag', 'tests', 'log'].includes(v)) poll(); } }, icon(VIEW_ICONS[v]), h('span', {}, t('view.' + v)))));

  const st = state.status, pe = document.getElementById('status'), banner = document.getElementById('banner');
  let msg = null, settingsLink = false;
  if (st?.mode === 'run' && !st.decrypting) { msg = t('banner.nokey'); settingsLink = true; }
  if (st?.mode === 'run' && st.waiting_for_dataset) { msg = t('banner.waiting'); settingsLink = true; }
  const sx = st?.stats || {};
  if (st?.mode === 'run' && sx.mle_failed > 0 && sx.mle_failed >= sx.mle_ok) { msg = t('banner.decrypt'); settingsLink = true; }
  if (st?.diagnostics_error && !msg) { msg = t('banner.diag') + st.diagnostics_error; settingsLink = false; }
  if (st?.capture_error) { msg = t('banner.error') + st.capture_error; settingsLink = false; }
  if (state.notice) { msg = state.notice.text; settingsLink = false; }
  banner.hidden = !msg;
  fill(banner, msg, msg && settingsLink ? h('button', { type: 'button', style: 'margin-left:12px', onclick: openSettings }, t('settings')) : null);
  pe.className = 'status' + (st && st.mode === 'run' && !st.capture_running ? ' bad' : '');
  pe.textContent = !st ? '' : st.mode === 'demo' ? t('status.demo') : st.waiting_for_dataset ? t('status.waiting') : st.capture_running ? t('status.live') : t('status.stopped');

  const view = document.getElementById('view');
  const topo = state.topo;
  const sel = document.getElementById('partition');
  if (!topo) { view.replaceChildren(); return; }
  if (state.partition == null || !topo.partitions.some(p => p.id === state.partition)) state.partition = topo.partitions[0]?.id ?? null;
  sel.replaceChildren(...topo.partitions.map(p => h('option', { value: p.id, selected: p.id === state.partition }, `${t('partition')} ${p.id.toString(16)} (${Object.values(topo.nodes).filter(n => n.partition_id === p.id && !n.placeholder).length})`)));
  sel.hidden = topo.partitions.length < 2;
  const p = partitionData();
  if (!['tests', 'log'].includes(state.view) && (!p || Object.values(topo.nodes).filter(n => !n.placeholder).length === 0)) { view.replaceChildren(h('div', { class: 'empty' }, t('empty'))); renderDrawer(); return; }
  const scroll = [view.scrollLeft, view.scrollTop];
  view.replaceChildren(state.view === 'tree' ? renderTree(p) : state.view === 'mesh' ? renderMesh(p) : state.view === 'table' ? renderTable(p) : state.view === 'tests' ? renderTests() : state.view === 'log' ? renderLog() : renderDiagnose());
  [view.scrollLeft, view.scrollTop] = scroll;
  if (['diag', 'tests', 'log'].includes(state.view)) document.getElementById('drawer').hidden = true;
  else renderDrawer();
}

async function poll() {
  const statusEl = document.getElementById('status');
  try {
    const [topo, status] = await Promise.all([fetch('/api/topology').then(r => r.json()), fetch('/api/status').then(r => r.json())]);
    state.topo = topo; state.status = status;
    if (state.view === 'diag') await loadDiagnostics();
    if (state.view === 'tests') await loadTests();
    if (state.view === 'log') await loadLog();
  } catch (err) {
    statusEl.textContent = '⚠'; statusEl.title = String(err);  // server unreachable
    return;
  }
  try {
    // never rebuild the page while the user is typing in a field: it would drop the input
    if (!document.activeElement || !['INPUT', 'SELECT'].includes(document.activeElement.tagName)) render();
    statusEl.title = '';
  } catch (err) {  // a bug in the UI: say so instead of silently showing stale content
    console.error(err);
    statusEl.textContent = '⚠ UI'; statusEl.title = String(err);
  }
}

async function init() {
  const stored = (() => { try { return localStorage.getItem('lang'); } catch { return null; } })();
  state.lang = stored || (navigator.language.startsWith('de') ? 'de' : 'en');
  for (const l of ['en', 'de']) state.dicts[l] = await fetch(`/i18n/${l}.json`).then(r => r.json());
  const langSel = document.getElementById('lang');
  langSel.value = state.lang;
  langSel.addEventListener('change', () => { state.lang = langSel.value; try { localStorage.setItem('lang', state.lang); } catch { /* ignore */ } render(); renderLegend(); renderSettings(); });
  document.getElementById('partition').addEventListener('change', e => { state.partition = Number(e.target.value); render(); });
  document.getElementById('settings-btn').addEventListener('click', openSettings);
  document.getElementById('rebuild-btn').addEventListener('click', rebuildTree);
  document.getElementById('diag-btn').addEventListener('click', () => setDiagEnabled(!!state.status?.diagnostics_paused));
  document.getElementById('legend-btn').addEventListener('click', () => { renderLegend(); document.getElementById('legend').showModal(); });
  render();
  loadConfig().then(render);
  await poll();
  setInterval(poll, 3000);
}
init();
