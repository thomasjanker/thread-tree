'use strict';
// Small line icons (24 x 24, drawn with the current text colour) for buttons and tabs. Uses s() of app.js.

const ICONS = {
  tree: ['M12 3v5', 'M12 8H5v4', 'M12 8h7v4', 'M5 16v5', 'M19 16v5', { rect: [9, 2, 6, 4] }, { rect: [2, 12, 6, 4] }, { rect: [16, 12, 6, 4] }],
  mesh: ['M7.5 8.5l9-3', 'M7 10l4 8', 'M17.5 7l-5 11', { circle: [5, 9, 2.5] }, { circle: [19, 5, 2.5] }, { circle: [12, 19, 2.5] }],
  table: [{ rect: [3, 4, 18, 16] }, 'M3 10h18', 'M3 15h18', 'M9 4v16'],
  diag: ['M3 12h4l3-8 4 16 3-8h4'],
  tests: ['M9 3h6', 'M10 3v6l-5.5 9.5A2 2 0 0 0 6.2 21h11.6a2 2 0 0 0 1.7-2.5L14 9V3', 'M7.5 15h9'],
  log: ['M9 6h12', 'M9 12h12', 'M9 18h12', { circle: [4.5, 6, 1] }, { circle: [4.5, 12, 1] }, { circle: [4.5, 18, 1] }],
  rebuild: ['M3 12a9 9 0 1 0 2.6-6.4L3 8', 'M3 3v5h5'],
  settings: ['M4 21v-7', 'M4 10V3', 'M12 21v-9', 'M12 8V3', 'M20 21v-5', 'M20 12V3', 'M1 14h6', 'M9 8h6', 'M17 16h6'],
  legend: [{ circle: [12, 12, 9] }, 'M9.2 9a3 3 0 0 1 5.8 1c0 2-3 2.5-3 4', 'M12 17.5v.01'],
  antenna: ['M4.9 19.1a10 10 0 0 1 0-14.2', 'M19.1 4.9a10 10 0 0 1 0 14.2', 'M7.8 16.2a6 6 0 0 1 0-8.4', 'M16.2 7.8a6 6 0 0 1 0 8.4', { circle: [12, 12, 2] }],
  refresh: ['M21 12a9 9 0 1 1-2.6-6.4L21 8', 'M21 3v5h-5'],
  download: ['M12 3v12', 'M7 10l5 5 5-5', 'M5 21h14'],
  trash: ['M3 6h18', 'M8 6V4h8v2', 'M6 6l1 15h10l1-15', 'M10 11v6', 'M14 11v6'],
  play: [{ path: 'M7 4v16l13-8z', fill: true }],
  stop: [{ rect: [6, 6, 12, 12], fill: true }],
  back: ['M15 18l-6-6 6-6'],
  close: ['M6 6l12 12', 'M18 6L6 18'],
  json: ['M8 4H6a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h2', 'M16 4h2a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-2'],
  locate: [{ circle: [12, 12, 7] }, { circle: [12, 12, 2] }, 'M12 2v3', 'M12 19v3', 'M2 12h3', 'M19 12h3'],
};

function icon(name) {
  const svg = s('svg', { class: 'icon', viewBox: '0 0 24 24', width: 16, height: 16, 'aria-hidden': 'true' });
  for (const part of ICONS[name] || []) {
    if (typeof part === 'string') svg.append(s('path', { d: part }));
    else if (part.rect) svg.append(s('rect', { x: part.rect[0], y: part.rect[1], width: part.rect[2], height: part.rect[3], rx: 1, class: part.fill ? 'filled' : null }));
    else if (part.circle) svg.append(s('circle', { cx: part.circle[0], cy: part.circle[1], r: part.circle[2] }));
    else if (part.path) svg.append(s('path', { d: part.path, class: part.fill ? 'filled' : null }));
  }
  return svg;
}

// a button (or link) with an icon in front of its text
function iconButton(name, text, attrs) {
  return h(attrs && attrs.href ? 'a' : 'button', { type: attrs && attrs.href ? null : 'button', ...(attrs || {}),
    class: `ibtn${attrs && attrs.href ? ' btnlink' : ''}${attrs && attrs.class ? ' ' + attrs.class : ''}` }, icon(name), h('span', {}, text));
}
