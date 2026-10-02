'use strict';

const ROLES = ['leader', 'router', 'fed', 'med', 'sed', 'child', 'unknown'];
const TYPES = ['rloc', 'aloc', 'ml-eid', 'omr', 'link-local'];
const VIEWS = ['tree', 'mesh', 'table'];
const state = { lang: 'en', dicts: {}, config: null, topo: null, status: null, view: 'tree', partition: null, selected: null, filter: '' };

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
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v);
  }
  el.append(...kids.flat(Infinity).filter(k => k != null));
  return el;
}
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
function roleLabel(role) { return t('role.' + role); }
function nodeName(n) {
  if (n.placeholder) return t(n.role === 'router' ? 'placeholder.router' : n.role === 'detached' ? 'placeholder.detached' : 'placeholder.' + n.role);
  return n.ext ? '…' + n.ext.slice(-8) : (n.rloc16 || n.id);
}
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
  g.append(s('title', {}, [nodeName(n), n.rloc16, roleLabel(n.role)].filter(Boolean).join(' · ')));
  g.append(s('rect', { class: 'card', width: CARD_W, height: CARD_H, rx: 8 }));
  g.append(...glyph(n, 20, CARD_H / 2, 12));
  g.append(s('text', { x: 40, y: 16 }, nodeName(n)));
  g.append(s('text', { x: 40, y: 31, class: 'sub' }, [n.rloc16, n.placeholder ? '' : roleLabel(n.role)].filter(Boolean).join(' · ')));
  if (!n.placeholder && !n.heard) {  // known only from other nodes' traffic
    g.append(s('circle', { cx: CARD_W - 12, cy: CARD_H - 11, r: 5, class: 'indirect' }, s('title', {}, t('reach.indirect'))));
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
function renderMesh(p) {
  const routers = Object.values(state.topo.nodes).filter(n => n.partition_id === p.id && ['leader', 'router'].includes(n.role));
  const R = Math.max(140, routers.length * 26), size = R * 2 + 2 * (CARD_W / 2 + PAD);
  const cx = size / 2, cy = R + CARD_H + PAD;
  const svg = s('svg', { width: size, height: R * 2 + CARD_H * 3, role: 'img', 'aria-label': t('view.mesh') });
  const at = new Map(routers.map((n, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, routers.length) - Math.PI / 2;
    return [n.id, { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) }];
  }));
  const seen = new Set();
  for (const l of state.topo.links) {
    const a = at.get(l.from), b = at.get(l.to);
    const key = [l.from, l.to].sort().join('|');
    if (!a || !b || seen.has(key)) continue;
    seen.add(key);
    const lq = Math.max(l.lq_in, l.lq_out);
    const line = s('line', { class: 'edge link', x1: a.x, y1: a.y, x2: b.x, y2: b.y, 'stroke-width': 1 + lq, opacity: lq ? 1 : .3 });
    line.append(s('title', {}, `${t('link.in')} ${l.lq_in} / ${t('link.out')} ${l.lq_out} / ${t('link.cost')} ${l.cost}`));
    svg.append(line);
  }
  for (const n of routers) {
    const a = at.get(n.id);
    svg.append(nodeCard(n, a.x - CARD_W / 2, a.y - CARD_H / 2, () => select(n.id)));
  }
  return svg;
}

// ---- table view ------------------------------------------------------------
function searchText(n) {
  return [n.role, roleLabel(n.role), n.rloc16, n.ext, n.border_router ? 'br' : '', ...n.addresses.map(a => a.addr)].join(' ').toLowerCase();
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
    .filter(n => !state.filter || searchText(n).includes(state.filter.toLowerCase()))
    .sort((a, b) => (a.rloc16 || '~').localeCompare(b.rloc16 || '~'));
  const input = h('input', { type: 'search', placeholder: t('filter'), value: state.filter, 'aria-label': t('filter') });
  input.addEventListener('input', () => {
    state.filter = input.value; render();
    const fresh = document.querySelector('#view input');  // render() replaced the element
    if (fresh) { fresh.focus(); fresh.setSelectionRange(fresh.value.length, fresh.value.length); }
  });
  const head = h('tr', {}, ...['col.role', 'col.rloc16', 'col.ext', 'col.reach', 'col.addresses', 'col.seen'].map(k => h('th', {}, t(k))));
  const body = rows.map(n => h('tr', { class: `row${n.online ? '' : ' offline'}${state.selected === n.id ? ' selected' : ''}`, onclick: () => select(n.id) },
    h('td', {}, roleChip(n.role), ' ', n.border_router ? abbr('BR') : null), h('td', { class: 'mono' }, n.rloc16 || '—'),
    h('td', { class: 'mono' }, n.ext || '—'), h('td', {}, reachLabel(n)), h('td', {}, addressList(n, true)), h('td', {}, ago(n.last_seen))));
  return h('div', {}, h('div', { class: 'toolbar' }, input), h('table', {}, h('thead', {}, head), h('tbody', {}, body)));
}

// ---- drawer ----------------------------------------------------------------
function findInTree(n, id) {
  if (n.id === id) return n;
  for (const c of n.children) { const r = findInTree(c, id); if (r) return r; }
  return null;
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
  d.replaceChildren(
    h('h2', {}, nodeName(n), roleChip(n.role), n.border_router ? abbr('BR') : null,
      h('button', { type: 'button', style: 'margin-left:auto', onclick: () => select(null), 'aria-label': t('legend.close') }, '×')),
    h('dl', {},
      dd(t('d.state'), t(n.online ? 'online' : 'offline')),
      dd(abbr('EUI-64'), h('span', { class: 'mono' }, n.ext || '—')),
      dd(abbr('RLOC16'), h('span', { class: 'mono' }, n.rloc16 || '—')),
      dd(t('d.mode'), Array.isArray(mode) ? [abbr(mode[0]), ' · ' + mode[1]] : mode),
      dd(t('col.partition'), String(n.partition_id)),
      n.parent ? dd(t('d.parent'), nodeLink(n.parent)) : [],
      dd(t('d.reach'), reachLabel(n), n.heard ? ` (${ago(n.last_heard)})` : ''),
      dd(t('d.first'), ago(n.first_seen)), dd(t('d.last'), ago(n.last_seen))),
    tn && tn.children.length ? [h('h3', {}, t('d.children')), h('div', {}, tn.children.map(c => h('div', {}, nodeLink(c.id))))] : [],
    links.length ? [h('h3', {}, t('d.neighbors')), ...links.map(l => h('div', {}, nodeLink(l.from === n.id ? l.to : l.from),
      ` — ${t('link.in')} ${l.lq_in} / ${t('link.out')} ${l.lq_out} / ${t('link.cost')} ${l.cost}`))] : [],
    h('h3', {}, t('d.addresses')), addressList(n, false));
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
      [h('span', { class: 'tag reach-direct' }, t('reach.direct')), h('span', {}, t('legend.direct'))]),
    h('h3', {}, t('legend.edges')),
    grid([h('span', { class: 'chip', style: 'background:var(--router)' }, '━'), t('legend.edge.link')],
      [h('span', { class: 'chip', style: 'background:var(--line);color:var(--text)' }, '─'), t('legend.edge.child')],
      [h('span', { class: 'chip', style: 'background:var(--muted)' }, '┄'), t('legend.edge.unknown')]),
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
  document.getElementById('legend-btn').textContent = t('legend');
  document.getElementById('settings-btn').textContent = t('settings');
  const views = document.getElementById('views');
  views.replaceChildren(...VIEWS.map(v => h('button', { type: 'button', role: 'tab', 'aria-selected': String(v === state.view), onclick: () => { state.view = v; render(); } }, t('view.' + v))));

  const st = state.status, pe = document.getElementById('status'), banner = document.getElementById('banner');
  let msg = null, settingsLink = false;
  if (st?.mode === 'run' && !st.decrypting) { msg = t('banner.nokey'); settingsLink = true; }
  if (st?.mode === 'run' && st.waiting_for_dataset) { msg = t('banner.waiting'); settingsLink = true; }
  const sx = st?.stats || {};
  if (st?.mode === 'run' && sx.mle_failed > 0 && sx.mle_failed >= sx.mle_ok) { msg = t('banner.decrypt'); settingsLink = true; }
  if (st?.capture_error) { msg = t('banner.error') + st.capture_error; settingsLink = false; }
  banner.hidden = !msg;
  banner.replaceChildren(...(msg ? [msg, settingsLink ? h('button', { type: 'button', style: 'margin-left:12px', onclick: openSettings }, t('settings')) : null] : []));
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
  if (!p || Object.values(topo.nodes).filter(n => !n.placeholder).length === 0) { view.replaceChildren(h('div', { class: 'empty' }, t('empty'))); renderDrawer(); return; }
  const scroll = [view.scrollLeft, view.scrollTop];
  view.replaceChildren(state.view === 'tree' ? renderTree(p) : state.view === 'mesh' ? renderMesh(p) : renderTable(p));
  [view.scrollLeft, view.scrollTop] = scroll;
  renderDrawer();
}

async function poll() {
  try {
    const [topo, status] = await Promise.all([fetch('/api/topology').then(r => r.json()), fetch('/api/status').then(r => r.json())]);
    state.topo = topo; state.status = status;
    if (!document.activeElement || document.activeElement.tagName !== 'INPUT') render();
    else renderDrawer();
  } catch { document.getElementById('status').textContent = '⚠'; }
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
  document.getElementById('legend-btn').addEventListener('click', () => { renderLegend(); document.getElementById('legend').showModal(); });
  render();
  await poll();
  setInterval(poll, 3000);
}
init();
