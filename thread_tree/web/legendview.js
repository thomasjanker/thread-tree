'use strict';
// The legend view: what the symbols, colours and abbreviations mean, and how Thread's protocol stack fits together.
// Uses h(), t(), abbr() and the role helpers of app.js.

// the layers of the stack, top down: [key, colour class, protocols]
const STACK_LAYERS = [
  ['app', 'l-app', ['Matter', 'SRP / DNS-SD', 'CoAP']],
  ['ctrl', 'l-ctrl', ['MLE', 'TMF']],
  ['transport', 'l-transport', ['UDP', 'ICMPv6']],
  ['network', 'l-network', ['IPv6']],
  ['adapt', 'l-adapt', ['6LoWPAN']],
  ['mac', 'l-mac', ['IEEE 802.15.4 MAC']],
  ['phy', 'l-phy', ['IEEE 802.15.4 PHY']],
];
// one frame on air: [key, colour class, relative width]
const FRAME_PARTS = [
  ['phy', 'l-phy', 6], ['mac', 'l-mac', 15], ['adapt', 'l-adapt', 8], ['udp', 'l-transport', 4],
  ['payload', 'l-ctrl', 28], ['mic', 'l-mac', 4], ['fcs', 'l-phy', 2],
];
// the way of a Matter command from the phone to a sleepy device
const PATH_STEPS = ['phone', 'br', 'router', 'parent', 'device'];

function stackSection() {
  const layers = h('div', { class: 'stack' }, STACK_LAYERS.map(([key, cls, protos]) =>
    h('div', { class: `stack-layer ${cls}` },
      h('div', { class: 'stack-name' }, h('strong', {}, t(`stack.${key}`)), h('span', { class: 'muted small' }, t(`stack.${key}.level`))),
      h('div', { class: 'stack-protos' }, protos.map(p => h('span', { class: 'stack-chip' }, p)), h('p', { class: 'small' }, t(`stack.${key}.what`))),
      h('div', { class: 'stack-sees small' }, h('span', { class: 'muted' }, t('stack.sees')), ' ', t(`stack.${key}.sees`)))));
  const frame = h('div', { class: 'frame-bar', role: 'img', 'aria-label': t('stack.frame') },
    FRAME_PARTS.map(([key, cls, w]) => h('div', { class: `frame-part ${cls}`, style: `flex:${w}`, title: t(`stack.frame.${key}.tip`) },
      h('strong', {}, t(`stack.frame.${key}`)), h('span', { class: 'small' }, t(`stack.frame.${key}.size`)))));
  const path = h('ol', { class: 'stack-path' }, PATH_STEPS.map(step =>
    h('li', {}, h('strong', {}, t(`stack.path.${step}`)), h('span', { class: 'small' }, t(`stack.path.${step}.what`)))));
  return [
    h('h3', {}, t('stack.title')),
    h('p', { class: 'small' }, t('stack.intro')),
    layers,
    h('div', { class: 'stack-keys small' }, h('strong', {}, t('stack.keys')), ' ', t('stack.keys.what')),
    h('h4', {}, t('stack.frame')),
    frame,
    h('p', { class: 'muted small' }, t('stack.frame.note')),
    h('h4', {}, t('stack.path')),
    path,
    h('p', { class: 'muted small' }, t('stack.path.note')),
  ];
}

function renderLegend() {
  const grid = (...rows) => h('div', { class: 'legend-grid' }, rows.flat());
  return h('div', { class: 'legend-page' },
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
      [h('span', { class: 'mesh-badge lq-3' }, '1'), t('legend.tree.linkcost')],
      [h('span', { class: 'cost-chip' }, tfill('tree.cost', { cost: 3 })), t('legend.tree.cost')],
      [h('span', { class: 'mesh-badge lq-3' }, '3'), t('legend.mesh.lq')],
      [h('span', { class: 'mesh-badge lq-1 lossy' }, '1'), t('legend.mesh.loss')]),
    h('h3', {}, t('legend.severity')),
    grid(['ok', 'info', 'warn', 'crit'].map(sev => [h('span', { class: `sev sev-${sev}` }, t('sev.' + sev)), h('span', {}, t('legend.sev.' + sev))])),
    h('h3', {}, t('legend.tests')),
    grid(['moved', 'searching', 'waiting'].map(st => [h('span', { class: `tag test-${st}` }, t('diag.test.status.' + st)), h('span', {}, t('legend.test.' + st))]),
      [h('span', { class: 'tag' }, 'CSL'), h('span', {}, t('legend.csl'))]),
    stackSection(),
    h('h3', {}, t('legend.types')),
    grid(TYPES.map(ty => [h('span', { class: 'tag' }, typeLabel(ty)), abbrDesc(ty)])),
    h('h3', {}, t('legend.sources')),
    grid([h('span', { class: 'tag' }, t('d.source.derived')), t('legend.source.derived')], [h('span', { class: 'tag' }, t('d.source.observed')), t('legend.source.observed')]),
    h('h3', {}, t('legend.abbr')),
    grid(Object.entries(dict().abbr).map(([k, [name, desc]]) => [h('strong', {}, k), h('span', {}, `${name}. ${desc}`)])));
}
