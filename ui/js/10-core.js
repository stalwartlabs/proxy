(function () {
  'use strict';

  var SVG_NS = 'http://www.w3.org/2000/svg';
  var D = { destinations: [], listeners: [], delays: [] };
  var API = window.PX_API;

  function h(tag, props) {
    var el = document.createElement(tag);
    if (props) {
      for (var k in props) {
        var v = props[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
        else if (k === 'value') el.value = v;
        else if (k === 'checked') el.checked = v;
        else el.setAttribute(k, v === true ? '' : v);
      }
    }
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }

  function append(el, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) {
      c.forEach(function (x) { append(el, x); });
    } else if (c instanceof Node) {
      el.appendChild(c);
    } else {
      el.appendChild(document.createTextNode(String(c)));
    }
  }

  function s(tag, attrs) {
    var el = document.createElementNS(SVG_NS, tag);
    for (var k in attrs) el.setAttribute(k, attrs[k]);
    for (var i = 2; i < arguments.length; i++) if (arguments[i]) el.appendChild(arguments[i]);
    return el;
  }

  function icon(name, cls) {
    var svg = s('svg', { viewBox: '0 0 24 24', class: 'icon' + (cls ? ' ' + cls : ''), 'aria-hidden': 'true' });
    (window.PX_ICONS[name] || []).forEach(function (n) { svg.appendChild(s(n[0], n[1])); });
    return svg;
  }

  function logo() {
    return s('svg', { viewBox: '95 84 500 90', class: 'logo', role: 'img', 'aria-label': 'Stalwart' },
      s('path', { fill: 'currentColor', d: window.PX_LOGO }),
      s('path', { fill: '#db2d54', d: 'M149.1 84.7h-4.8l-44.8 25.9v8.3l44.8 25.9h4.8l44.8-25.9v-8.3l-44.8-25.9zm32.9 30h-35.3V94.4l35.3 20.3zm-35.3 20.4-35.3-20.4 27-15.6v20.2l6.3 3.6h22.9l-20.9 12.2zM99.5 129.9v11l44.8 25.9h4.8l44.8-25.9v-11l-47.2 27.3zM187.3 166.8l6.6-3.8v-11l-25.7 14.8zM99.5 163l6.6 3.8h19.1L99.5 152z' }));
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  function ms(t) {
    return typeof t === 'string' ? Date.parse(t) : t;
  }

  var fmt = {
    n: function (v) { return v === null || v === undefined ? '-' : Number(v).toLocaleString('en-US'); },
    pct: function (v) { return v === null || v === undefined || isNaN(v) ? '-' : v.toFixed(v >= 99 ? 2 : 1) + '%'; },
    bytes: function (b) {
      var u = ['B', 'KB', 'MB', 'GB', 'TB'];
      var i = 0;
      while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
      return (i === 0 ? b : b.toFixed(b < 10 ? 1 : 0)) + ' ' + u[i];
    },
    ago: function (t) {
      var sec = Math.max(0, Math.round((Date.now() - ms(t)) / 1000));
      if (sec < 60) return sec + 's ago';
      if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
      if (sec < 86400) return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm ago';
      return Math.floor(sec / 86400) + 'd ago';
    },
    dur: function (sec) {
      sec = Math.max(0, Math.round(sec));
      if (sec < 60) return sec + 's';
      if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
      if (sec < 86400) return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
      return Math.floor(sec / 86400) + 'd ' + Math.floor((sec % 86400) / 3600) + 'h';
    },
    ttl: function (msv) {
      if (msv === null || msv === undefined) return '-';
      if (msv < 1000) return msv + 'ms';
      if (msv < 60000) return (msv / 1000) + 's';
      return fmt.dur(msv / 1000);
    },
    left: function (t) { return fmt.dur((ms(t) - Date.now()) / 1000); },
    time: function (t) { return new Date(ms(t)).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'; },
    proto: function (p) {
      return { imap: 'IMAP', pop3: 'POP3', managesieve: 'ManageSieve', submission: 'Submission', smtp: 'SMTP', lmtp: 'LMTP', http: 'HTTP' }[p] || p;
    }
  };

  function toast(title, desc, variant) {
    var vp = document.getElementById('toasts');
    var t = h('div', { class: 'toast' + (variant ? ' toast-' + variant : ''), role: 'status' },
      h('div', null, h('div', { class: 'toast-title', text: title }), desc ? h('div', { class: 'toast-description', text: desc }) : null),
      h('button', { class: 'toast-close', 'aria-label': 'Close', onclick: function () { t.remove(); } }, icon('x', 'icon-sm')));
    vp.appendChild(t);
    while (vp.children.length > 5) vp.firstChild.remove();
    setTimeout(function () { t.remove(); }, 4500);
  }

  var openDialogs = [];

  function dialog(opts) {
    var prevFocus = document.activeElement;
    var overlay = h('div', { class: 'overlay' });
    var box = h('div', { class: 'dialog' + (opts.cls ? ' ' + opts.cls : ''), role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'dlg-title' });
    function close() {
      overlay.remove();
      box.remove();
      document.removeEventListener('keydown', onKey);
      openDialogs = openDialogs.filter(function (d) { return d !== close; });
      if (opts.onClose) opts.onClose();
      if (prevFocus && prevFocus.focus) prevFocus.focus();
    }
    function onKey(e) {
      if (e.key === 'Escape' && openDialogs[openDialogs.length - 1] === close) close();
      if (e.key === 'Tab') {
        var f = box.querySelectorAll('button, input, select, textarea, a[href]');
        if (!f.length) return;
        if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
        else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
      }
    }
    overlay.addEventListener('click', close);
    if (!opts.bare) {
      append(box, [
        h('div', { class: 'dialog-header' },
          h('h2', { class: 'dialog-title', id: 'dlg-title', text: opts.title }),
          opts.description ? h('p', { class: 'dialog-description', text: opts.description }) : null),
        opts.body ? h('div', { class: 'dialog-body' }, opts.body) : null,
        opts.footer ? h('div', { class: 'dialog-footer' }, opts.footer(close)) : null,
        h('button', { class: 'dialog-close', 'aria-label': 'Close', onclick: close }, icon('x'))
      ]);
    } else {
      append(box, opts.body);
    }
    document.body.appendChild(overlay);
    document.body.appendChild(box);
    document.addEventListener('keydown', onKey);
    openDialogs.push(close);
    var first = box.querySelector('input, select, textarea') || box.querySelector('.dialog-footer .btn:last-child');
    if (first) setTimeout(function () { first.focus(); }, 0);
    return close;
  }

  function confirmDialog(opts) {
    dialog({
      title: opts.title,
      description: opts.description,
      body: opts.body,
      footer: function (close) {
        return [
          h('button', { class: 'btn btn-outline', text: 'Cancel', onclick: close }),
          h('button', { class: 'btn' + (opts.danger ? ' btn-danger' : ''), onclick: function () { close(); opts.onConfirm(); } }, opts.confirmIcon ? icon(opts.confirmIcon) : null, opts.confirm || 'Confirm')
        ];
      }
    });
  }

  function fail(e) {
    if (e && e.status === 401) return;
    toast('Request failed', e && e.message ? e.message : String(e), 'destructive');
  }

  function act(promise, title, desc) {
    return promise.then(function (data) {
      toast(title, typeof desc === 'function' ? desc(data) : desc, 'success');
      return data;
    }, function (e) {
      fail(e);
      throw e;
    });
  }

  function load(map) {
    var names = Object.keys(map);
    return Promise.all(names.map(function (k) { return API.get(map[k]); })).then(function (values) {
      names.forEach(function (k, i) { D[k] = values[i]; });
      return D;
    });
  }

  function badgeHealth(state) {
    var map = { up: ['badge-success', 'Up'], degraded: ['badge-warning', 'Degraded'], down: ['badge-destructive', 'Down'] };
    var m = map[state];
    return h('span', { class: 'badge ' + m[0] }, m[1]);
  }

  function dot(state) {
    return h('span', { class: 'dot' + (state === 'up' ? '' : ' dot-' + state), 'aria-hidden': 'true' });
  }

  function tlsChip(tls) {
    return h('span', { class: 'chip ' + (tls === 'plain' ? 'chip-plain' : 'chip-tls') }, tls);
  }

  function protoChips(protocols) {
    return h('div', { class: 'chips' }, Object.keys(protocols).map(function (p) {
      var e = protocols[p];
      return h('span', { class: 'chip', title: e.tls }, h('b', { text: fmt.proto(p) }), ':' + e.port + (e.tls === 'implicit' ? ' tls' : e.tls === 'starttls' ? ' starttls' : ' plain'));
    }));
  }

  function spark(values, cls) {
    var w = 120, hh = 36;
    if (values.length < 2) values = [values[0] || 0, values[0] || 0];
    var max = Math.max.apply(null, values), min = Math.min.apply(null, values);
    var span = max - min || 1;
    var pts = values.map(function (v, i) {
      return [(i / (values.length - 1)) * w, hh - 2 - ((v - min) / span) * (hh - 6)];
    });
    var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join('');
    return s('svg', { viewBox: '0 0 ' + w + ' ' + hh, 'aria-hidden': 'true', class: cls || '' },
      s('path', { d: line + 'L' + w + ' ' + hh + 'L0 ' + hh + 'Z', class: 'spark-area' }),
      s('path', { d: line, class: 'spark-line' }));
  }

  function areaChart(seriesList, opts) {
    var w = 720, hh = 330, padL = 36, padB = 22, padT = 10, padR = 8;
    seriesList.forEach(function (sr) { if (sr.values.length < 2) sr.values = [sr.values[0] || 0, sr.values[0] || 0]; });
    var n = seriesList[0].values.length;
    var max = 0;
    seriesList.forEach(function (sr) { sr.values.forEach(function (v) { if (sr.axis !== 'right' && v > max) max = v; }); });
    var rmax = 0;
    seriesList.forEach(function (sr) { if (sr.axis === 'right') sr.values.forEach(function (v) { if (v > rmax) rmax = v; }); });
    max = Math.ceil(max / 10) * 10 || 1;
    rmax = Math.ceil(rmax / 10) * 10 || 1;
    var svg = s('svg', { viewBox: '0 0 ' + w + ' ' + hh, class: 'chart', role: 'img', 'aria-label': opts.label });
    for (var g = 0; g <= 4; g++) {
      var y = padT + (hh - padT - padB) * (g / 4);
      svg.appendChild(s('line', { x1: padL, x2: w - padR, y1: y, y2: y, class: 'grid' }));
      var t = s('text', { x: padL - 6, y: y + 4, 'text-anchor': 'end', class: 'axis' });
      t.textContent = Math.round(max * (1 - g / 4));
      svg.appendChild(t);
    }
    var span = Math.max(1, Math.round((opts.span || 3600) / 60));
    [-span, -span * 3 / 4, -span / 2, -span / 4, 0].map(function (m) { return m ? Math.round(m) + 'm' : 'now'; }).forEach(function (lbl, i) {
      var tx = s('text', { x: padL + (w - padL - padR) * (i / 4), y: hh - 4, 'text-anchor': i === 0 ? 'start' : i === 4 ? 'end' : 'middle', class: 'axis' });
      tx.textContent = lbl;
      svg.appendChild(tx);
    });
    seriesList.forEach(function (sr) {
      var m = sr.axis === 'right' ? rmax : max;
      var pts = sr.values.map(function (v, i) {
        return [padL + (w - padL - padR) * (i / (n - 1)), padT + (hh - padT - padB) * (1 - v / m)];
      });
      var d = pts.map(function (p, i) { return (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1); }).join('');
      if (sr.area) svg.appendChild(s('path', { d: d + 'L' + (w - padR) + ' ' + (hh - padB) + 'L' + padL + ' ' + (hh - padB) + 'Z', class: sr.cls + 'a' }));
      svg.appendChild(s('path', { d: d, class: sr.cls, 'vector-effect': 'non-scaling-stroke' }));
    });
    return svg;
  }

  function tileHead(iconName, title, sub, actions) {
    return h('div', { class: 'tile-head' },
      h('div', { class: 'tile-header' },
        iconName ? h('span', { class: 'tile-icon' }, icon(iconName)) : null,
        h('div', null, h('h3', { class: 'section-title', text: title }), sub ? h('div', { class: 'tile-sub', text: sub }) : null)),
      actions ? h('div', { class: 'tile-head-actions' }, actions) : null);
  }

  function statTile(o) {
    return h('div', { class: 'tile stat span-3' + (o.tone ? ' tile-' + o.tone : '') },
      h('div', { class: 'stat-label' }, h('span', { class: 'tile-icon' }, icon(o.icon)), h('span', { text: o.label })),
      h('div', { class: 'stat-value', text: o.value }),
      h('div', { class: 'stat-foot' }, o.delta ? h('span', { class: 'delta ' + (o.deltaCls || '') }, o.delta) : h('span', { class: 'tile-sub', text: o.sub || '' }), o.spark ? spark(o.spark) : null));
  }

  function pageHeader(title, subtitle, actions, crumb) {
    return h('div', { class: 'page-header' },
      h('div', null,
        crumb ? h('a', { class: 'crumb', href: crumb.href }, icon('chevron-left', 'icon-sm'), crumb.label) : null,
        h('div', { class: 'title-row' }, h('h1', { class: 'page-title', text: title }), subtitle && subtitle.badge ? subtitle.badge : null),
        subtitle && subtitle.text ? h('p', { class: 'page-subtitle', text: subtitle.text }) : null),
      actions ? h('div', { class: 'page-actions' }, actions) : null);
  }

  function destById(id) {
    return D.destinations.filter(function (d) { return d.id === id; })[0];
  }

  function destSelect(value, opts) {
    opts = opts || {};
    return h('select', { class: 'select', id: opts.id, 'aria-label': 'Destination' },
      opts.any ? h('option', { value: '', text: 'All destinations' }) : null,
      D.destinations.filter(function (d) { return opts.any || Object.keys(d.protocols).some(function (p) { return p !== 'smtp' && p !== 'lmtp'; }); }).map(function (d) {
        return h('option', { value: d.id, selected: d.id === value ? 'selected' : null, text: d.id + (d.health.state !== 'up' ? '  (' + d.health.state + ')' : '') });
      }));
  }

  var routes = [];
  var timers = [];
  var gen = 0;

  function route(pattern, render, nav) {
    routes.push({ re: new RegExp('^' + pattern.replace(/:[a-z]+/g, '([^/]+)') + '$'), render: render, nav: nav });
  }

  function every(period, fn) {
    var id = setInterval(function () { if (!document.hidden) fn(); }, period);
    timers.push(id);
  }

  function poll(period, fn) {
    var busy = false, skip = 0, fails = 0, g = gen;
    every(period, function () {
      if (busy || g !== gen) return;
      if (skip > 0) { skip--; return; }
      busy = true;
      Promise.resolve().then(fn).then(function () { fails = 0; }, function () {
        fails++;
        skip = Math.min(12, Math.pow(2, fails) - 1);
      }).then(function () { busy = false; });
    });
  }

  function alive(g) {
    return g === gen;
  }

  function errorState(e, retry) {
    return h('div', { class: 'empty-state' },
      h('p', { text: e && e.message ? e.message : 'Request failed' }),
      retry ? h('button', { class: 'btn btn-outline btn-sm', onclick: retry }, icon('refresh-cw'), 'Retry') : null);
  }

  function page(root, loads, draw) {
    var g = gen;
    function run() {
      clear(root);
      root.appendChild(h('div', { class: 'loading' }, icon('refresh-cw'), 'Loading'));
      return load(typeof loads === 'function' ? loads() : loads).then(function () {
        if (g !== gen) return;
        clear(root);
        draw();
      }, function (e) {
        if (g !== gen) return;
        clear(root);
        root.appendChild(errorState(e, run));
      });
    }
    return run();
  }

  function navigate(hash) {
    if (location.hash === hash) render();
    else location.hash = hash;
  }

  function render() {
    timers.forEach(clearInterval);
    timers = [];
    gen++;
    var full = (location.hash || '#/').slice(1) || '/';
    var qi = full.indexOf('?');
    var path = qi >= 0 ? full.slice(0, qi) : full;
    PX.query = new URLSearchParams(qi >= 0 ? full.slice(qi + 1) : '');
    if (PX.session === undefined) {
      clear(document.getElementById('root')).appendChild(h('div', { class: 'loading loading-full' }, icon('refresh-cw'), 'Loading'));
      return;
    }
    if (!PX.session && path !== '/login') {
      PX.afterLogin = full;
      path = '/login';
    }
    for (var i = 0; i < routes.length; i++) {
      var m = path.match(routes[i].re);
      if (m) {
        var r = routes[i];
        var args = m.slice(1).map(decodeURIComponent);
        PX.shell(r.nav, function (content) { return r.render.apply(null, [content].concat(args)); });
        return;
      }
    }
    navigate('#/');
  }

  window.PX = {
    D: D,
    API: API,
    ms: ms,
    h: h,
    s: s,
    icon: icon,
    logo: logo,
    clear: clear,
    fmt: fmt,
    toast: toast,
    dialog: dialog,
    confirm: confirmDialog,
    fail: fail,
    act: act,
    load: load,
    page: page,
    poll: poll,
    alive: alive,
    gen: function () { return gen; },
    errorState: errorState,
    badgeHealth: badgeHealth,
    dot: dot,
    tlsChip: tlsChip,
    protoChips: protoChips,
    spark: spark,
    areaChart: areaChart,
    tileHead: tileHead,
    statTile: statTile,
    pageHeader: pageHeader,
    destById: destById,
    destSelect: destSelect,
    route: route,
    every: every,
    navigate: navigate,
    render: render,
    session: undefined,
    afterLogin: null
  };
})();
