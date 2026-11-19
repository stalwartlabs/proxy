(function () {
  'use strict';
  var PX = window.PX, h = PX.h, icon = PX.icon, D = PX.D, fmt = PX.fmt, API = PX.API, enc = API.enc;
  var PROTOCOL_OPTIONS = [['', 'Any protocol']].concat(['imap', 'pop3', 'managesieve', 'submission', 'http', 'smtp', 'lmtp'].map(function (p) { return [p, fmt.proto(p)]; }));

  function sum(a, f) { return a.reduce(function (t, x) { return t + f(x); }, 0); }

  function bucket(values, size) {
    var out = [];
    for (var i = 0; i < values.length; i += size) {
      var sl = values.slice(i, i + size);
      out.push(sum(sl, function (v) { return v; }) / sl.length);
    }
    return out;
  }

  function column(series, name) {
    var i = series.fields.indexOf(name);
    return series.points.map(function (p) { return p[i] || 0; });
  }

  function roleLabel(r) {
    return r === 'passthrough' ? 'pass-through' : r;
  }

  function replaceDest(d) {
    D.destinations = D.destinations.map(function (x) { return x.id === d.id ? d : x; });
    return d;
  }

  function resetHealth(d, after) {
    PX.act(API.request('POST', 'destinations/' + enc(d.id) + '/reset'), 'Health reset', d.id + ' is accepting connections again.')
      .then(function (updated) { replaceDest(updated); if (after) after(updated); }, function () {});
  }

  function ranking(rows, opts) {
    var max = Math.max.apply(null, rows.map(function (r) { return r[1]; }).concat([1]));
    return h('ul', { class: 'ranking' + (opts && opts.wide ? ' ranking-wide' : '') }, rows.map(function (r, i) {
      var bar = h('span', { class: 'ranking-bar' + (opts && opts.colors ? ' c' + ((i % 5) + 1) : '') });
      bar.style.width = Math.max(4, (r[1] / max) * 100) + '%';
      var label = opts && opts.label ? opts.label(r[0]) : r[0];
      return h('li', null,
        opts && opts.href ? h('a', { class: 'r-name', href: opts.href(r[0]), title: r[0], text: label }) : h('span', { class: 'r-name', text: label }),
        h('span', { class: 'ranking-track' }, bar),
        h('span', { class: 'r-val', text: fmt.n(r[1]) }));
    }));
  }

  function emptyNote(text) {
    return h('div', { class: 'tile-sub', text: text });
  }

  var eventIcon = { admin: 'user', health: 'activity', config: 'file-code', mapping: 'route' };

  function eventList(events) {
    return h('div', { class: 'events' }, events.map(function (e) {
      var meta = fmt.ago(e.at);
      if (e.actor) meta += ' by ' + e.actor + (e.ip ? ' from ' + e.ip : '');
      return h('div', { class: 'event' },
        h('span', { class: 'event-icon k-' + e.kind }, icon(eventIcon[e.kind] || 'info')),
        h('div', null, h('div', null, e.message, e.target ? h('span', { class: 'mono', text: ' ' + e.target }) : null), h('div', { class: 'event-meta', text: meta })));
    }));
  }

  function newestFirst(list) {
    return list.items.slice().reverse();
  }

  function restartBanner(keys) {
    return keys && keys.length ? h('div', { class: 'banner banner-warning' }, icon('triangle-alert'), h('div', { class: 'grow' }, h('b', { text: 'Restart required. ' }), 'Saved changes to ' + keys.join(', ') + ' take effect after the proxy restarts.')) : null;
  }

  function setupStep(state, title, text, href, action) {
    return h('li', { class: 'setup-step' + (state === 'done' ? ' is-done' : '') },
      h('span', { class: 'setup-mark' }, icon(state === 'done' ? 'check' : state === 'optional' ? 'info' : 'circle-alert')),
      h('div', { class: 'grow' },
        h('div', { class: 'setup-title' }, h('b', { text: title }), state === 'optional' ? h('span', { class: 'badge badge-secondary', text: 'Optional' }) : null),
        h('div', { class: 'tile-sub', text: text })),
      state === 'done' ? null : h('a', { class: 'btn btn-secondary btn-sm', href: href }, action, icon('chevron-right')));
  }

  function needsSetup() {
    return !D.destinations.length || !D.listeners.length;
  }

  function setupGuide() {
    var list = h('ol', { class: 'setup-list' });
    var tile = h('div', { class: 'tile tile-pad span-12 setup-tile' },
      PX.tileHead('settings', 'Set up the proxy', 'Nothing is routed yet. Work through these steps; each change is validated and applied live.'),
      list);
    API.get('config').then(function (conf) {
      var v = conf.values;
      var certs = Object.keys((v.tls && v.tls.certificate) || {}).filter(function (id) { return id !== 'admin'; });
      var routing = v.routing && v.routing.default_destination;
      var steps = [
        setupStep(D.destinations.length ? 'done' : 'todo', 'Add a destination', 'A mail backend the proxy forwards authenticated sessions to.', '#/destinations/new', 'New destination'),
        setupStep(routing ? 'done' : 'todo', 'Choose the default destination', 'In [routing]: where logins without a mapping go.', '#/config?section=routing', 'Routing'),
        setupStep(v.mapping ? 'done' : 'optional', 'Connect a mapping store', 'File (inside mappings/ next to the configuration), Redis or SQL table that pins accounts to destinations. Without one every login goes to the default destination.', '#/config?section=mapping', 'Mapping'),
        setupStep(certs.length ? 'done' : 'optional', 'Add a TLS certificate', 'Needed for implicit TLS and STARTTLS listeners on your mail host names.', '#/config?tab=certificates', 'Certificates'),
        setupStep(D.listeners.length ? 'done' : 'todo', 'Add listeners', 'Ports the proxy accepts IMAP, POP3, submission, ManageSieve or HTTP on. Requires the default destination.', '#/listeners/new', 'New listener')
      ];
      if (!conf.writable) list.appendChild(h('div', { class: 'banner banner-info' }, icon('lock'), h('div', { class: 'grow' }, 'Configuration writes are disabled (admin.config_write = false); edit ' + conf.path + ' on the host and reload.')));
      steps.forEach(function (st) { list.appendChild(st); });
    }, function (e) { list.appendChild(emptyNote(e.message)); });
    return tile;
  }

  function refresher(loads, draw) {
    var g = PX.gen();
    return function () {
      return PX.load(loads).then(function () { if (PX.alive(g)) draw(); });
    };
  }

  PX.route('/', function (root) {
    var loads = { overview: 'overview', series: 'metrics/series', destinations: 'destinations', listeners: 'listeners', events: 'events' };
    function draw() {
      PX.clear(root);
      var o = D.overview, sr = D.series, hc = o.destinations;
      var act = column(sr, 'active'), lg = column(sr, 'auth_ok'), rej = column(sr, 'auth_rejected');
      var perMin = 60 / sr.interval_s;
      var rejected = sum(rej.slice(-perMin), function (v) { return v; });
      var first = act.length ? act[0] : 0;
      var change = first ? ((o.sessions.active - first) / first) * 100 : 0;
      var byProto = Object.keys(o.sessions.by_protocol).map(function (k) { return [k, o.sessions.by_protocol[k]]; }).filter(function (r) { return r[1] > 0; }).sort(function (a, b) { return b[1] - a[1]; });
      var span = sr.points.length * sr.interval_s;
      var page = h('div', { class: 'page' },
        PX.pageHeader('Overview', { text: 'Live state of ' + location.hostname + '. Refreshes every 5 seconds while this tab is visible.' },
          [h('button', { class: 'btn btn-outline btn-sm', onclick: function () { refresher(loads, draw)().then(null, PX.fail); } }, icon('refresh-cw'), 'Refresh')]),
        restartBanner(o.config.restart_required),
        h('div', { class: 'bento' },
          needsSetup() ? setupGuide() : null,
          PX.statTile({ icon: 'cable', label: 'Active sessions', value: fmt.n(o.sessions.active), spark: bucket(act, perMin), delta: act.length > 1 ? (change >= 0 ? '+' : '') + change.toFixed(1) + '% vs ' + fmt.dur(span) + ' ago' : null, deltaCls: change >= 0 ? 'delta-good' : '' }),
          PX.statTile({ icon: 'key-round', label: 'Logins per minute', value: fmt.n(sum(lg.slice(-perMin), function (v) { return v; })), spark: bucket(lg, perMin), delta: rejected + ' rejected last min', deltaCls: rejected > 2 ? 'delta-bad' : '' }),
          PX.statTile({ icon: 'gauge', label: 'Cache hit rate', value: fmt.pct(o.cache.hit_rate_pct), sub: o.cache.max_bytes !== undefined ? fmt.n(o.cache.entries) + ' entries in ' + fmt.bytes(o.cache.max_bytes) : fmt.n(o.cache.entries) + ' of ' + fmt.n(o.cache.max_entries) + ' entries' }),
          PX.statTile({ icon: 'server', label: 'Destinations up', value: hc.up + ' / ' + hc.total, tone: hc.down ? 'accent' : null, delta: hc.up < hc.total ? hc.down + ' down, ' + hc.degraded + ' degraded' : 'all healthy', deltaCls: hc.down ? 'delta-bad' : 'delta-good' }),
          h('div', { class: 'tile tile-pad span-8 rows-2 chart-tile' },
            PX.tileHead('activity', 'Traffic', 'Last ' + fmt.dur(span) + ', 1 minute buckets of ' + sr.interval_s + ' second samples', h('div', { class: 'legend' }, h('span', null, h('i', { class: 'l1' }), 'Active sessions'), h('span', null, h('i', { class: 'l2' }), 'Logins per minute'), h('span', null, h('i', { class: 'l3' }), 'Rejected per minute'))),
            PX.areaChart([
              { values: bucket(act, perMin), cls: 's1', area: true },
              { values: bucket(lg, perMin).map(function (v) { return v * perMin; }), cls: 's2' },
              { values: bucket(rej, perMin).map(function (v) { return v * perMin; }), cls: 's3' }
            ], { label: 'Traffic over the last hour', span: span })),
          h('div', { class: 'tile tile-pad span-4 rows-2' },
            PX.tileHead('server', 'Destination health', null, h('a', { class: 'btn btn-ghost btn-sm', href: '#/destinations' }, 'All', icon('chevron-right'))),
            D.destinations.length ? null : emptyNote('No destinations yet.'),
            h('div', { class: 'health-list' }, D.destinations.map(function (d) {
              var meta = [h('span', null, d.sessions + ' sessions')];
              if (d.health.state !== 'up') {
                meta.push(h('span', null, d.health.consecutive_failures + ' failures'));
                meta.push(h('span', null, d.health.failure_sources + ' client' + (d.health.failure_sources === 1 ? '' : 's')));
                if (d.health.down_until) meta.push(h('span', { class: 'countdown' }, 'retry in ' + fmt.left(d.health.down_until)));
              }
              if (d.roles.length) meta.push(h('span', null, d.roles.map(roleLabel).join(', ')));
              return h('div', { class: 'health-row' },
                h('a', { class: 'health-name', href: '#/destinations/' + enc(d.id) }, PX.dot(d.health.state), d.id),
                d.health.state === 'up' ? PX.badgeHealth('up') : h('button', { class: 'btn btn-secondary btn-sm', onclick: function () { resetHealth(d, draw); } }, icon('rotate-ccw'), 'Reset'),
                h('div', { class: 'health-meta' }, meta));
            }))),
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('radio-tower', 'Sessions by protocol', fmt.n(o.open_connections) + ' open connections, including pre-auth'), byProto.length ? ranking(byProto, { label: fmt.proto, colors: true }) : emptyNote('No sessions.')),
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('users', 'Top identifiers', 'By live sessions'),
            o.top_identifiers.length ? ranking(o.top_identifiers.map(function (t) { return [t.identifier, t.sessions]; }), { wide: true, href: function (id) { return '#/connections?identifier=' + enc(id); } }) : emptyNote('No identified sessions.')),
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('history', 'Recent activity', null, h('a', { class: 'btn btn-ghost btn-sm', href: '#/activity' }, 'All', icon('chevron-right'))),
            D.events.items.length ? eventList(newestFirst(D.events).slice(0, 4)) : emptyNote('No events yet.')),
          h('div', { class: 'tile tile-flat span-12' },
            h('div', { class: 'status-strip' },
              icon('file-code'),
              h('span', null, 'Config ', h('b', { class: 'mono', text: o.config.path || '(no path)' })),
              h('span', null, 'revision ', h('b', { class: 'mono', text: o.config.revision })),
              h('span', null, 'loaded ', h('b', { text: fmt.ago(o.config.loaded_at) })),
              h('span', null, 'writes ', h('b', { text: o.config.writable ? 'enabled' : 'disabled' })),
              h('span', { class: 'grow' }),
              h('a', { class: 'btn btn-outline btn-sm', href: '#/config' }, icon('settings'), 'Configuration')))));
      root.appendChild(page);
    }
    PX.page(root, loads, draw);
    PX.poll(5000, refresher(loads, draw));
  }, 'overview');

  PX.route('/destinations', function (root) {
    var filter = { state: '', proto: '' };
    var tbody = h('tbody');
    var countEl = h('span', { class: 'tile-sub' });
    function rows() {
      PX.clear(tbody);
      countEl.textContent = D.destinations.length + ' destinations';
      D.destinations.filter(function (d) {
        return (!filter.state || d.health.state === filter.state) && (!filter.proto || d.protocols[filter.proto]);
      }).forEach(function (d) {
        var href = '#/destinations/' + enc(d.id);
        tbody.appendChild(h('tr', { class: 'is-link', onclick: function (e) { if (!e.target.closest('button, a')) location.hash = href; } },
          h('td', null, h('a', { class: 'row-link', href: href, text: d.id }), h('span', { class: 'sub mono', text: d.host + (d.tls_server_name ? ' (' + d.tls_server_name + ')' : '') })),
          h('td', null, PX.protoChips(d.protocols)),
          h('td', null, d.forwarding === 'proxy' ? 'PROXY v2' : d.forwarding === 'xclient' ? 'XCLIENT / ID' : 'none'),
          h('td', null, { platform: 'Platform', pinned: 'Pinned SHA-256', insecure: 'Not verified' }[d.tls_verify], d.tls_client_cert ? h('span', { class: 'sub', text: 'mutual TLS' }) : null),
          h('td', null, d.roles.length ? h('div', { class: 'chips' }, d.roles.map(function (r) { return h('span', { class: 'badge badge-secondary', text: roleLabel(r) }); })) : h('span', { class: 'text-dim', text: '-' })),
          h('td', null, PX.badgeHealth(d.health.state)),
          h('td', { class: 'num' }, fmt.n(d.sessions)),
          h('td', { class: 'num' }, d.roles.indexOf('default') >= 0 ? h('span', { class: 'text-dim', text: 'fallback' }) : fmt.n(d.mapped_identifiers))));
      });
      if (!tbody.firstChild) tbody.appendChild(h('tr', null, h('td', { colspan: '8', class: 'table-empty' }, D.destinations.length ? 'No destinations match the filters.' : ['No destinations yet. ', h('a', { href: '#/destinations/new', text: 'Add the first backend' }), ', then pick it as the default destination in ', h('a', { href: '#/config?section=routing', text: 'routing' }), '.'])));
    }
    function sel(label, key, opts) {
      return h('select', { class: 'select', 'aria-label': label, onchange: function (e) { filter[key] = e.target.value; rows(); } },
        opts.map(function (o) { return h('option', { value: o[0], text: o[1] }); }));
    }
    function draw() {
      root.appendChild(h('div', { class: 'page' },
        PX.pageHeader('Destinations', { text: 'Backends the proxy routes to, with live circuit-breaker state.' },
          [h('a', { class: 'btn', href: '#/destinations/new' }, icon('plus'), 'New destination')]),
        allowSlot('destination'),
        h('div', { class: 'tile-table' },
          h('div', { class: 'toolbar' },
            sel('Health', 'state', [['', 'Any health'], ['up', 'Up'], ['degraded', 'Degraded'], ['down', 'Down']]),
            sel('Protocol', 'proto', PROTOCOL_OPTIONS),
            h('span', { class: 'grow' }),
            countEl),
          h('div', { class: 'table-wrap' },
            h('table', { class: 'table' },
              h('thead', null, h('tr', null, ['Name', 'Endpoints', 'Forwarding', 'Backend TLS', 'Role', 'Health', 'Sessions', 'Mapped'].map(function (t, i) { return h('th', { class: i >= 6 ? 'num' : null, text: t }); }))),
              tbody)))));
      rows();
    }
    PX.page(root, { destinations: 'destinations' }, draw);
    PX.poll(5000, refresher({ destinations: 'destinations' }, rows));
  }, 'destinations');

  function allowSlot(kind) {
    var slot = h('div', { class: 'contents' });
    API.get('config').then(function (conf) {
      var banner = PX.allowBanner(conf, kind);
      if (banner) slot.appendChild(banner);
    }, function () {});
    return slot;
  }

  function destRefs(id, values) {
    var refs = [];
    if (!values) return refs;
    var routing = values.routing || {};
    if (routing.default_destination === id) refs.push('routing.default_destination');
    if (routing.smtp_passthrough_destination === id) refs.push('routing.smtp_passthrough_destination');
    (values.http.route || []).forEach(function (r, i) {
      if (r.destination === id) refs.push('http.route[' + i + '].destination');
      if (r.fallback === id) refs.push('http.route[' + i + '].fallback');
    });
    return refs;
  }

  PX.route('/destinations/:id', function (root, id) {
    if (id === 'new') return PX.destinationForm(root, null);
    var path = 'destinations/' + enc(id);
    var conf = null;
    var g = PX.gen();
    function draw() {
      PX.clear(root);
      var d = replaceDest(D.destination);
      var hl = d.health;
      var lf = hl.last_failure;
      var values = conf && conf.values;
      var refs = destRefs(d.id, values);
      var counts = {};
      D.destConns.items.forEach(function (c) { if (c.identifier) counts[c.identifier] = (counts[c.identifier] || 0) + 1; });
      var top = Object.keys(counts).map(function (k) { return [k, counts[k]]; }).sort(function (a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : 1); }).slice(0, 5);
      var threshold = values ? values.server.host_down_threshold : null;
      var minClients = values ? values.server.host_down_min_clients : null;
      root.appendChild(h('div', { class: 'page' },
        PX.pageHeader(d.id, { badge: PX.badgeHealth(hl.state), text: d.host + (d.tls_server_name ? ', TLS name ' + d.tls_server_name : '') }, [
          hl.state !== 'up' ? h('button', { class: 'btn btn-outline', onclick: function () { resetHealth(d, function (u) { D.destination = u; draw(); }); } }, icon('rotate-ccw'), 'Reset health') : null,
          h('a', { class: 'btn btn-outline', href: '#/destinations/' + enc(d.id) + '/edit' }, icon('pencil'), 'Edit'),
          conf && conf.writable ? h('button', { class: 'btn btn-ghost-danger btn-icon', 'aria-label': 'Delete', title: 'Delete', onclick: function () {
            if (refs.length || d.mapped_identifiers) {
              PX.dialog({ title: 'Cannot delete ' + d.id, description: 'This destination is still referenced. Remove the references first.', body: h('ul', { class: 'stack' }, refs.map(function (r) { return h('li', { class: 'mono', text: r }); }).concat(d.mapped_identifiers ? [h('li', { text: d.mapped_identifiers + ' mappings point to it' })] : [])), footer: function (close) { return [h('button', { class: 'btn', text: 'OK', onclick: close })]; } });
            } else {
              PX.applyOps(conf, [{ op: 'remove', path: ['destination', d.id] }], { done: function () { PX.navigate('#/destinations'); } });
            }
          } }, icon('trash-2')) : null
        ], { href: '#/destinations', label: 'Destinations' }),
        hl.state === 'down' ? h('div', { class: 'banner banner-danger' }, icon('circle-alert'), h('div', { class: 'grow' }, h('b', { text: 'Circuit open. ' }), 'New logins routed here fail fast until the cooldown ends in ', h('span', { class: 'countdown', text: fmt.left(hl.down_until) }), '. Existing sessions are not affected.')) : null,
        h('div', { class: 'bento' },
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('activity', 'Health'),
            h('dl', { class: 'kv' },
              h('dt', { text: 'State' }), h('dd', null, PX.badgeHealth(hl.state)),
              h('dt', { text: 'Failure streak' }), h('dd', { text: hl.consecutive_failures + (threshold !== null ? ' of ' + threshold : '') }),
              h('dt', { text: 'Distinct clients' }), h('dd', { text: hl.failure_sources + (minClients !== null ? ' of ' + minClients + ' needed' : '') }),
              h('dt', { text: 'Host-level failure' }), h('dd', { text: hl.host_level_failure ? 'Yes (connect stage)' : 'No' }),
              h('dt', { text: 'Last failure' }), h('dd', null, lf ? [fmt.ago(lf.at) + ', ' + lf.class + ' failure (stage ' + lf.stage + ')', h('span', { class: 'sub mono', text: lf.error })] : 'None'))),
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('network', 'Endpoints'),
            h('table', { class: 'table' }, h('tbody', null, Object.keys(d.protocols).map(function (p) {
              var e = d.protocols[p];
              return h('tr', null, h('td', { text: fmt.proto(p) }), h('td', { class: 'mono', text: d.host + ':' + e.port }), h('td', null, PX.tlsChip(e.tls)), h('td', { class: 'text-dim', text: e.forwarding }));
            })))),
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('shield-check', 'Backend TLS and auth'),
            h('dl', { class: 'kv' },
              h('dt', { text: 'Verification' }), h('dd', { text: { platform: 'Platform verifier', pinned: 'Pinned SHA-256', insecure: 'Disabled (insecure)' }[d.tls_verify] }),
              h('dt', { text: 'Client certificate' }), h('dd', { text: d.tls_client_cert ? 'Yes (mutual TLS)' : 'No' }),
              h('dt', { text: 'Plaintext auth' }), h('dd', { text: d.allow_plaintext_auth ? 'Allowed' : 'Refused' }),
              h('dt', { text: 'Hide auth errors' }), h('dd', { text: d.hide_auth_errors ? 'Yes' : 'No' }))),
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('arrow-up-right', 'Client forwarding'),
            h('dl', { class: 'kv' },
              h('dt', { text: 'Mode' }), h('dd', { text: d.forwarding === 'proxy' ? 'PROXY protocol v2' : d.forwarding === 'xclient' ? 'XCLIENT / IMAP ID' : 'None' }),
              h('dt', { text: 'Forwarded header' }), h('dd', { text: d.forwarded ? 'Added on HTTP' : 'Not added' }),
              h('dt', { text: 'Source IPs' }), h('dd', { class: 'mono', text: d.source_ips.length ? d.source_ips.join(', ') : 'system default' }))),
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('route', 'Routing'),
            h('dl', { class: 'kv' },
              h('dt', { text: 'Roles' }), h('dd', { text: d.roles.length ? d.roles.map(roleLabel).join(', ') : 'none' }),
              h('dt', { text: 'Referenced by' }), h('dd', { class: 'mono', text: refs.length ? refs.join(', ') : values ? 'nothing' : 'unknown' }),
              h('dt', { text: 'Mapped identifiers' }), h('dd', { text: d.mapped_identifiers === null ? 'n/a' : fmt.n(d.mapped_identifiers) }),
              h('dt', { text: 'Live sessions' }), h('dd', { text: fmt.n(d.sessions) }))),
          h('div', { class: 'tile tile-pad span-4' }, PX.tileHead('users', 'Top identifiers here', null, h('a', { class: 'btn btn-ghost btn-sm', href: '#/connections?destination=' + enc(d.id) }, 'Sessions', icon('chevron-right'))),
            top.length ? ranking(top, { wide: true, href: function (x) { return '#/connections?identifier=' + enc(x); } }) : emptyNote('No identified sessions.')))));
    }
    var loads = { destination: path, destConns: 'connections' + API.query({ destination: id, limit: 1000 }) };
    PX.page(root, loads, draw);
    API.get('config').then(function (c) { conf = c; if (PX.alive(g) && D.destination && D.destination.id === id) draw(); }, function () {});
    PX.poll(5000, refresher({ destination: path }, draw));
    PX.every(1000, function () {
      var until = D.destination && D.destination.id === id && D.destination.health.down_until;
      if (until) root.querySelectorAll('.countdown').forEach(function (el) { el.textContent = fmt.left(until); });
    });
  }, 'destinations');

  PX.route('/destinations/:id/edit', function (root, id) { PX.destinationForm(root, id); }, 'destinations');

  PX.route('/listeners', function (root) {
    var tbody = h('tbody');
    function rows() {
      PX.clear(tbody);
      var pass = D.destinations.filter(function (d) { return d.roles.indexOf('passthrough') >= 0; })[0];
      D.listeners.forEach(function (l) {
        var pct = Math.min(100, (l.sessions / l.max_connections) * 100);
        var bar = h('span', { class: 'ranking-bar' + (pct > 80 ? ' warn' : '') });
        bar.style.width = Math.max(2, pct) + '%';
        var href = '#/listeners/' + enc(l.id);
        var passthrough = l.protocol === 'smtp' || l.protocol === 'lmtp';
        tbody.appendChild(h('tr', { class: 'is-link', onclick: function (e) { if (!e.target.closest('a')) location.hash = href; } },
          h('td', null, h('a', { class: 'row-link', href: href, text: l.id })),
          h('td', null, fmt.proto(l.protocol), passthrough ? h('span', { class: 'sub', text: 'pass-through' + (pass ? ' to ' + pass.id : '') }) : null),
          h('td', { class: 'mono' }, l.bind.join(', ')),
          h('td', null, PX.tlsChip(l.tls)),
          h('td', null, l.proxy_protocol === 'off' ? h('span', { class: 'text-dim', text: 'off' }) : [l.proxy_protocol, h('span', { class: 'sub mono', text: l.proxy_trusted.join(', ') })]),
          h('td', null, h('div', { class: 'usage' }, h('span', { class: 'ranking-track' }, bar), h('span', { text: fmt.n(l.sessions) + ' / ' + fmt.n(l.max_connections) }))),
          h('td', { class: 'num' }, fmt.n(l.accepted), l.rejected_limit ? h('span', { class: 'sub', text: fmt.n(l.rejected_limit) + ' over limit' }) : null)));
      });
      if (!D.listeners.length) {
        var hasDefault = D.destinations.some(function (d) { return d.roles.indexOf('default') >= 0; });
        tbody.appendChild(h('tr', null, h('td', { colspan: '7', class: 'table-empty' }, hasDefault
          ? ['No listeners yet. ', h('a', { href: '#/listeners/new', text: 'Add a listener' }), ' to start accepting mail clients; it binds as soon as it is saved.']
          : ['No listeners yet. Listeners need a default destination: ', h('a', { href: D.destinations.length ? '#/config?section=routing' : '#/destinations/new', text: D.destinations.length ? 'choose one in routing' : 'add a destination' }), ' first.'])));
      }
    }
    var loads = { listeners: 'listeners', destinations: 'destinations' };
    PX.page(root, loads, function () {
      root.appendChild(h('div', { class: 'page' },
        PX.pageHeader('Listeners', { text: 'Sockets the proxy accepts on. Saved changes bind, rebind or close sockets live; open sessions keep running.' }, [h('a', { class: 'btn', href: '#/listeners/new' }, icon('plus'), 'New listener')]),
        allowSlot('listener'),
        h('div', { class: 'tile-table' }, h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
          h('thead', null, h('tr', null, ['Name', 'Protocol', 'Bind', 'TLS', 'Inbound PROXY', 'Usage', 'Accepted'].map(function (t, i) { return h('th', { class: i === 6 ? 'num' : null, text: t }); }))),
          tbody)))));
      rows();
    });
    PX.poll(5000, refresher({ listeners: 'listeners' }, rows));
  }, 'listeners');

  PX.route('/listeners/:id', function (root, id) {
    PX.listenerForm(root, id === 'new' ? null : id);
  }, 'listeners');

  function delayDialog(identifier, after) {
    var idInput = h('input', { class: 'input', value: identifier || '', placeholder: 'user@example.com', 'aria-label': 'Identifier' });
    var secs = h('input', { class: 'input', type: 'number', min: '0', value: '300', 'aria-label': 'Seconds' });
    var presets = h('div', { class: 'preset-row' }, [[60, '1 min'], [300, '5 min'], [900, '15 min'], [3600, '1 hour']].map(function (p) {
      return h('button', { class: 'btn btn-secondary btn-sm', type: 'button', onclick: function () { secs.value = p[0]; } }, p[1]);
    }));
    PX.dialog({
      title: 'Delay logins',
      description: 'New logins for this identifier are held (up to 2 minutes each) until the delay ends. Use it while moving a mailbox: delay, kick, change the mapping. Changing the mapping or invalidating the cache entry releases the delay.',
      body: [h('label', { class: 'field' }, h('span', { class: 'field-label', text: 'Identifier' }), idInput),
        h('label', { class: 'field' }, h('span', { class: 'field-label', text: 'Duration (seconds)' }), secs), presets],
      footer: function (close) {
        return [h('button', { class: 'btn btn-outline', text: 'Cancel', onclick: close }),
          h('button', { class: 'btn', onclick: function () {
            var id = idInput.value.trim();
            var n = Number(secs.value);
            if (!id) { idInput.setAttribute('aria-invalid', 'true'); return; }
            if (!(n >= 0) || Math.floor(n) !== n) { secs.setAttribute('aria-invalid', 'true'); return; }
            close();
            PX.act(API.request('PUT', 'delays/' + enc(id), { json: { seconds: n } }), n ? 'Logins delayed' : 'Delay released', n ? id + ' for ' + fmt.dur(n) : id)
              .then(function () { if (after) after(); else PX.navigate('#/connections?tab=delays'); }, function () {});
          } }, icon('hourglass'), 'Delay')];
      }
    });
  }

  function kick(body, label, after) {
    PX.confirm({
      title: 'Kick ' + label + '?',
      description: 'The sessions are closed immediately on both legs. Clients usually reconnect and are routed again from the current mapping.',
      danger: true, confirm: 'Kick', confirmIcon: 'unplug',
      onConfirm: function () {
        PX.act(API.request('POST', 'connections/kick', { json: body }), 'Sessions kicked', function (r) { return r.kicked + ' session' + (r.kicked === 1 ? '' : 's') + ' closed (' + label + ')'; })
          .then(after, function () {});
      }
    });
  }

  PX.route('/connections', function (root) {
    var tab = PX.query.get('tab') === 'delays' ? 'delays' : 'sessions';
    var f = { identifier: PX.query.get('identifier') || '', protocol: '', destination: PX.query.get('destination') || '', listener: '' };
    var cursors = [];
    var cursor = '';
    var selected = {};
    var auto = true;
    var typing = null;
    var body = h('div');
    var bar = h('div', { class: 'action-bar-wrap hidden' });
    var tabs = h('div', { class: 'tabs-list', role: 'tablist' });
    var g = PX.gen();

    function connPath() {
      return 'connections' + API.query({ identifier: f.identifier, protocol: f.protocol, destination: f.destination, listener: f.listener, cursor: cursor, limit: 100 });
    }

    function fetchTab() {
      return tab === 'sessions' ? PX.load({ connections: connPath(), delays: 'delays' }) : PX.load({ delays: 'delays' });
    }

    function refresh() {
      return fetchTab().then(function () { if (PX.alive(g)) draw(); });
    }

    function drawBar() {
      var ids = Object.keys(selected).map(Number);
      PX.clear(bar);
      bar.classList.toggle('hidden', ids.length === 0);
      bar.appendChild(h('div', { class: 'action-bar' },
        h('span', { class: 'action-bar-dot' }),
        h('span', { class: 'btn btn-ink btn-sm', text: ids.length + ' selected' }),
        h('span', { class: 'action-bar-divider' }),
        h('button', { class: 'btn btn-ink btn-sm', onclick: function () { selected = {}; draw(); } }, 'Clear'),
        h('button', { class: 'btn btn-ink-danger btn-sm', onclick: function () { kick({ ids: ids }, ids.length + ' selected sessions', function () { selected = {}; refresh(); }); } }, icon('unplug'), 'Kick selected')));
    }

    function sessionsView() {
      var page = D.connections;
      var list = page.items;
      var idIn = h('input', { class: 'input', type: 'search', placeholder: 'Identifier prefix', value: f.identifier, 'aria-label': 'Identifier', oninput: function (e) {
        f.identifier = e.target.value;
        clearTimeout(typing);
        typing = setTimeout(function () { cursors = []; cursor = ''; refresh().then(null, PX.fail); }, 300);
      } });
      function filterSel(label, key, opts) {
        return h('select', { class: 'select', 'aria-label': label, onchange: function (e) { f[key] = e.target.value; cursors = []; cursor = ''; refresh().then(null, PX.fail); } },
          opts.map(function (o) { return h('option', { value: o[0], selected: f[key] === o[0] ? 'selected' : null, text: o[1] }); }));
      }
      return h('div', { class: 'tile-table' },
        h('div', { class: 'toolbar' },
          idIn,
          filterSel('Protocol', 'protocol', PROTOCOL_OPTIONS),
          filterSel('Destination', 'destination', [['', 'All destinations']].concat(D.destinations.map(function (d) { return [d.id, d.id]; }))),
          filterSel('Listener', 'listener', [['', 'All listeners']].concat(D.listeners.map(function (l) { return [l.id, l.id]; }))),
          h('span', { class: 'grow' }),
          h('label', { class: 'field-inline tile-sub' }, 'Auto-refresh', h('button', { class: 'toggle', role: 'switch', 'aria-checked': String(auto), 'aria-label': 'Auto-refresh', onclick: function () { auto = !auto; draw(); } }))),
        f.identifier && list.length ? h('div', { class: 'toolbar' }, h('div', { class: 'banner banner-info grow' }, icon('info'), h('div', { class: 'grow' }, page.total + ' sessions match "' + f.identifier + '".'),
          h('button', { class: 'btn btn-secondary btn-sm', onclick: function () { delayDialog(f.identifier); } }, icon('hourglass'), 'Delay logins'),
          h('button', { class: 'btn btn-danger btn-sm', onclick: function () { kick({ ids: list.map(function (c) { return c.id; }) }, list.length + ' listed sessions', refresh); } }, icon('unplug'), 'Kick listed'))) : null,
        h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
          h('thead', null, h('tr', null,
            h('th', { class: 'check-col' }, h('input', { type: 'checkbox', class: 'checkbox', 'aria-label': 'Select all', checked: list.length > 0 && list.every(function (c) { return selected[c.id]; }), onchange: function (e) { list.forEach(function (c) { if (e.target.checked) selected[c.id] = true; else delete selected[c.id]; }); draw(); } })),
            ['Identifier', 'Protocol', 'Client', 'Destination', 'Started', 'Down / Up', ''].map(function (t, i) { return h('th', { class: i === 5 ? 'num' : null, text: t }); }))),
          h('tbody', null, list.length ? list.map(function (c) {
            return h('tr', { class: selected[c.id] ? 'is-selected' : null },
              h('td', { class: 'check-col' }, h('input', { type: 'checkbox', class: 'checkbox', checked: !!selected[c.id], 'aria-label': 'Select', onchange: function (e) { if (e.target.checked) selected[c.id] = true; else delete selected[c.id]; draw(); } })),
              h('td', null, c.identifier ? h('a', { class: 'row-link', href: '#/connections?identifier=' + enc(c.identifier), text: c.identifier }) : h('span', { class: 'text-dim', text: '(pass-through)' }), h('span', { class: 'sub', text: 'session #' + c.id })),
              h('td', null, fmt.proto(c.protocol), h('span', { class: 'sub', text: c.listener || '' })),
              h('td', null, h('span', { class: 'mono', text: c.client }), h('span', { class: 'sub', text: c.client_tls ? 'TLS' : 'plain' })),
              h('td', null, c.destination ? h('a', { href: '#/destinations/' + enc(c.destination), text: c.destination }) : '-', h('span', { class: 'sub mono', text: c.backend + (c.backend_tls ? ' TLS' : ' plain') })),
              h('td', { title: fmt.time(c.started_at), text: fmt.ago(c.started_at) }),
              h('td', { class: 'num', text: fmt.bytes(c.bytes_down) + ' / ' + fmt.bytes(c.bytes_up) }),
              h('td', { class: 'actions' },
                c.identifier ? h('button', { class: 'btn btn-ghost btn-icon-sm', title: 'Delay logins', 'aria-label': 'Delay logins', onclick: function () { delayDialog(c.identifier); } }, icon('hourglass')) : null,
                h('button', { class: 'btn btn-ghost-danger btn-icon-sm', title: 'Kick session', 'aria-label': 'Kick session', onclick: function () { kick({ ids: [c.id] }, 'session #' + c.id, refresh); } }, icon('unplug'))));
          }) : h('tr', null, h('td', { colspan: '8', class: 'table-empty', text: 'No sessions match the filters.' }))))),
        h('div', { class: 'pagination' }, h('span', { text: 'Showing ' + list.length + ' of ' + fmt.n(page.total) + ' sessions (pre-auth connections are not listed)' }),
          h('div', { class: 'pagination-buttons' },
            h('button', { class: 'btn btn-secondary btn-sm', disabled: cursors.length ? null : true, onclick: function () { cursor = cursors.pop() || ''; refresh().then(null, PX.fail); } }, 'Previous'),
            h('button', { class: 'btn btn-secondary btn-sm', disabled: page.next_cursor ? null : true, onclick: function () { cursors.push(cursor); cursor = page.next_cursor; refresh().then(null, PX.fail); } }, 'Next'))));
    }

    function delaysView() {
      return h('div', { class: 'tile-table' },
        h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
          h('thead', null, h('tr', null, ['Identifier', 'Remaining', 'Until', 'Held logins', ''].map(function (t) { return h('th', { text: t }); }))),
          h('tbody', null, D.delays.length ? D.delays.map(function (dl) {
            return h('tr', null,
              h('td', null, h('a', { class: 'row-link', href: '#/connections?identifier=' + enc(dl.identifier), text: dl.identifier })),
              h('td', { class: 'countdown', 'data-until': dl.until, text: fmt.left(dl.until) }),
              h('td', { text: fmt.time(dl.until) }),
              h('td', { text: String(dl.waiting) }),
              h('td', { class: 'actions' },
                h('button', { class: 'btn btn-secondary btn-sm', onclick: function () { delayDialog(dl.identifier, refresh); } }, 'Extend'),
                ' ',
                h('button', { class: 'btn btn-outline btn-sm', onclick: function () {
                  PX.act(API.request('DELETE', 'delays/' + enc(dl.identifier)), 'Delay released', dl.identifier + (dl.waiting ? ': ' + dl.waiting + ' held logins proceed now' : ''))
                    .then(refresh, function () {});
                } }, 'Release')));
          }) : h('tr', null, h('td', { colspan: '5', class: 'table-empty', text: 'No logins are being delayed.' }))))));
    }

    function tabBtn(id, label, count) {
      return h('button', { class: 'tab', role: 'tab', 'aria-selected': String(tab === id), onclick: function () {
        tab = id;
        selected = {};
        refresh().then(null, PX.fail);
      } }, label, count !== null ? h('span', { class: 'badge badge-secondary badge-sm', text: String(count) }) : null);
    }

    function draw() {
      var focused = document.activeElement && document.activeElement.type === 'search' && body.contains(document.activeElement);
      var caret = focused ? document.activeElement.selectionStart : null;
      PX.clear(tabs);
      tabs.appendChild(tabBtn('sessions', 'Sessions', D.connections ? D.connections.total : null));
      tabs.appendChild(tabBtn('delays', 'Login delays', D.delays.length));
      PX.clear(body);
      body.appendChild(tab === 'sessions' ? sessionsView() : delaysView());
      drawBar();
      if (focused) {
        var i = body.querySelector('input[type=search]');
        if (i) { i.focus(); i.setSelectionRange(caret, caret); }
      }
    }

    var first = { destinations: 'destinations', listeners: 'listeners', delays: 'delays' };
    D.connections = null;
    if (tab === 'sessions') first.connections = connPath();
    PX.page(root, first, function () {
      root.appendChild(h('div', { class: 'page' },
        PX.pageHeader('Connections', { text: 'Authenticated sessions currently bridged to a backend.' }, [h('button', { class: 'btn btn-outline', onclick: function () { delayDialog(''); } }, icon('hourglass'), 'Delay logins')]),
        h('div', null, tabs), body, bar));
      draw();
    });
    PX.every(1000, function () {
      root.querySelectorAll('[data-until]').forEach(function (el) { el.textContent = fmt.left(el.getAttribute('data-until')); });
    });
    PX.poll(5000, function () {
      if (!auto || Object.keys(selected).length || (document.activeElement && document.activeElement.type === 'search')) return null;
      return refresh();
    });
  }, 'connections');

  function mappingDialog(m, store, after) {
    var isNew = !m || m.isNew;
    var idIn = h('input', { class: 'input', value: m ? m.identifier : '', placeholder: 'user@example.com', disabled: isNew ? null : true, 'aria-label': 'Identifier' });
    var sel = PX.destSelect(m ? m.destination : (D.destinations[0] || {}).id);
    PX.dialog({
      title: isNew ? 'Add mapping' : 'Edit mapping',
      description: 'Writes to the mapping store, invalidates the cache entry and releases any login delay. Existing sessions stay where they are until kicked.',
      body: [h('label', { class: 'field' }, h('span', { class: 'field-label', text: 'Identifier' }), idIn,
        h('p', { class: 'field-help', text: 'A master user suffix is removed and the rest is normalised' + (store && store.normalize ? ' (mapping.normalize = ' + store.normalize + ')' : '') + ' before it is stored.' })),
        h('label', { class: 'field' }, h('span', { class: 'field-label', text: 'Destination' }), sel)],
      footer: function (close) {
        return [h('button', { class: 'btn btn-outline', text: 'Cancel', onclick: close }),
          h('button', { class: 'btn', onclick: function () {
            var id = idIn.value.trim();
            if (!id || /[\s"]/.test(id)) { idIn.setAttribute('aria-invalid', 'true'); return; }
            close();
            PX.act(API.request('PUT', 'mappings/' + enc(id), { json: { destination: sel.value } }), 'Mapping saved', function (r) { return r.normalized + ' routes to ' + r.destination + (r.created ? ' (new)' : ''); })
              .then(after, function () {});
          } }, icon('save'), 'Save')];
      }
    });
  }

  function parseTsv(text) {
    var entries = [], bad = 0;
    text.split('\n').forEach(function (l) {
      var t = l.trim();
      if (!t || t[0] === '#') return;
      var p = t.split(/\s+/);
      if (p.length === 2) entries.push(p); else bad++;
    });
    return { entries: entries, bad: bad };
  }

  function importDialog(after) {
    var ta = h('textarea', { class: 'textarea mono', rows: '8', placeholder: 'alice@example.com\tstalwart-a\nbob@example.com\tstalwart-b', 'aria-label': 'Mappings TSV' });
    var preview = h('div', { class: 'field-help', text: 'One mapping per line: identifier, whitespace, destination. Same format as the file store.' });
    var file = h('input', { type: 'file', accept: '.tsv,.txt,text/plain', class: 'hidden', onchange: function () {
      var fl = file.files && file.files[0];
      if (!fl) return;
      var reader = new FileReader();
      reader.onload = function () { ta.value = String(reader.result); update(); };
      reader.readAsText(fl);
    } });
    function update() {
      var r = parseTsv(ta.value);
      preview.textContent = r.entries.length + ' entries' + (r.bad ? ', ' + r.bad + ' malformed lines skipped' : '');
    }
    ta.addEventListener('input', update);
    function send(entries, total, errors) {
      if (!entries.length) return Promise.resolve({ upserted: total, errors: errors });
      return API.request('POST', 'mappings/import', { json: { entries: entries.slice(0, 5000) } }).then(function (r) {
        return send(entries.slice(5000), total + r.upserted, errors + r.errors.length);
      });
    }
    PX.dialog({
      title: 'Import mappings', cls: 'dialog-lg',
      description: 'Merges into the store in batches of 5000. Existing identifiers are overwritten.',
      body: [ta, preview, file, h('button', { class: 'btn btn-secondary btn-sm', type: 'button', onclick: function () { file.click(); } }, icon('upload'), 'Choose .tsv file')],
      footer: function (close) {
        return [h('button', { class: 'btn btn-outline', text: 'Cancel', onclick: close }),
          h('button', { class: 'btn', onclick: function () {
            var r = parseTsv(ta.value);
            if (!r.entries.length) { ta.setAttribute('aria-invalid', 'true'); return; }
            close();
            PX.act(send(r.entries, 0, 0), 'Imported', function (res) { return res.upserted + ' mappings written' + (res.errors ? ', ' + res.errors + ' rejected (unknown destination or invalid identifier)' : ''); })
              .then(after, function () {});
          } }, icon('upload'), 'Import')];
      }
    });
  }

  function lookupResult(r, sessions, store, onChange) {
    var d = PX.destById(r.destination);
    function step(label, v) { return h('div', { class: 'route-step' }, h('small', { text: label }), h('span', { class: 'mono', text: v })); }
    var mapped = !r.routed_to_default;
    var stale = !r.store_error && r.cache.state !== 'miss' && (r.store_value ? r.store_value !== r.destination : mapped);
    return h('div', { class: 'lookup-result' },
      h('div', { class: 'route-flow' },
        step('Presented', r.identifier), icon('chevron-right'),
        r.account !== r.identifier ? [step('Master user stripped', r.account), icon('chevron-right')] : null,
        step('Normalized', r.key), icon('chevron-right'),
        step(mapped ? 'Mapping' : 'No mapping, default', r.destination || '-')),
      stale ? h('div', { class: 'banner banner-warning' }, icon('triangle-alert'), h('div', { class: 'grow' }, 'The cached route differs from the store. Invalidate the cache entry to apply the stored mapping.')) : null,
      h('dl', { class: 'kv' },
        h('dt', { text: 'Store value' }), h('dd', { class: 'mono', text: r.store_error ? 'store error' : r.store_value || '(none)' }),
        h('dt', { text: 'Final destination' }), h('dd', null, r.destination ? h('a', { href: '#/destinations/' + enc(r.destination), text: r.destination }) : '-', ' ', d ? PX.badgeHealth(d.health.state) : null),
        h('dt', { text: 'Cache' }), h('dd', { text: r.cache.state + (r.cache.ttl_remaining_s !== null ? ', expires in ' + fmt.dur(r.cache.ttl_remaining_s) : '') }),
        h('dt', { text: 'Live sessions' }), h('dd', { text: String(sessions) })),
      h('div', { class: 'page-actions' },
        store.writable ? h('button', { class: 'btn btn-outline btn-sm', onclick: function () { mappingDialog({ identifier: r.key, destination: r.store_value || r.destination, isNew: !r.store_value }, store, onChange); } }, icon('pencil'), r.store_value ? 'Change destination' : 'Add mapping') : null,
        h('button', { class: 'btn btn-outline btn-sm', onclick: function () {
          PX.act(API.request('POST', 'cache/invalidate', { json: { identifier: r.key } }), 'Cache entry invalidated', r.key).then(onChange, function () {});
        } }, icon('refresh-cw'), 'Invalidate cache'),
        h('a', { class: 'btn btn-outline btn-sm', href: '#/connections?identifier=' + enc(r.key) }, icon('cable'), 'Sessions')));
  }

  PX.route('/mappings', function (root) {
    var prefix = '';
    var cursors = [];
    var cursor = '';
    var conf = null;
    var g = PX.gen();
    var typing = null;
    var tbody = h('tbody');
    var pag = h('div', { class: 'pagination' });
    var storeTile = h('div', { class: 'tile tile-pad span-4' });
    var actions = h('div', { class: 'page-actions' });
    var lookupOut = h('div');
    var lookupIn = h('input', { class: 'input', type: 'search', placeholder: 'Identifier as the client sends it, e.g. Alice.Lee@Northwind.test*admin', 'aria-label': 'Identifier to look up' });

    function store() {
      var m = D.mappings;
      var mp = conf && conf.values && conf.values.mapping;
      return { source: m.source, writable: m.writable, listable: m.listable, total: m.total, normalize: mp ? mp.normalize : null, path: mp && mp.file ? mp.file.path : null };
    }

    function listPath() {
      return 'mappings' + API.query({ prefix: prefix, cursor: cursor, limit: 50 });
    }

    function reload() {
      return PX.load({ mappings: listPath(), destinations: 'destinations' }).then(function () { if (PX.alive(g)) { rows(); drawSide(); } });
    }

    function doLookup() {
      var v = lookupIn.value.trim();
      PX.clear(lookupOut);
      if (!v) return;
      API.request('GET', 'mappings/lookup' + API.query({ identifier: v })).then(function (r) {
        return API.request('GET', 'connections' + API.query({ identifier: r.key, limit: 1000 })).then(function (c) {
          return c.items.filter(function (x) { return x.identifier === r.key; }).length;
        }, function () { return 0; }).then(function (n) {
          if (!PX.alive(g)) return;
          PX.clear(lookupOut);
          lookupOut.appendChild(lookupResult(r, n, store(), function () { reload().then(doLookup, PX.fail); }));
        });
      }, PX.fail);
    }
    lookupIn.addEventListener('keydown', function (e) { if (e.key === 'Enter') doLookup(); });

    function rows() {
      var m = D.mappings, st = store();
      PX.clear(tbody);
      m.items.forEach(function (x) {
        var d = PX.destById(x.destination);
        tbody.appendChild(h('tr', null,
          h('td', { class: 'mono', text: x.identifier }),
          h('td', null, d ? h('a', { class: 'health-name', href: '#/destinations/' + enc(x.destination) }, PX.dot(d.health.state), x.destination) : h('span', { class: 'mono', title: 'Not a declared destination; routed to the default', text: x.destination + ' (undeclared)' })),
          h('td', { class: 'actions' }, st.writable ? [
            h('button', { class: 'btn btn-ghost btn-icon-sm', title: 'Edit', 'aria-label': 'Edit', onclick: function () { mappingDialog(x, st, reload); } }, icon('pencil')),
            h('button', { class: 'btn btn-ghost-danger btn-icon-sm', title: 'Delete', 'aria-label': 'Delete', onclick: function () {
              PX.confirm({ title: 'Delete mapping?', description: x.identifier + ' will fall back to the default destination on its next login.', danger: true, confirm: 'Delete', onConfirm: function () {
                PX.act(API.request('DELETE', 'mappings/' + enc(x.identifier)), 'Mapping deleted', x.identifier).then(reload, function () {});
              } });
            } }, icon('trash-2'))] : null)));
      });
      if (!m.items.length && !m.source) tbody.appendChild(h('tr', null, h('td', { colspan: '3', class: 'table-empty' }, 'No mapping store configured, so every login goes to the default destination. ', h('a', { href: '#/config?section=mapping', text: 'Connect a file, Redis or SQL store' }), ' to pin accounts to destinations.')));
      else if (!m.items.length) tbody.appendChild(h('tr', null, h('td', { colspan: '3', class: 'table-empty', text: !m.listable ? 'This store cannot be listed. A SQL store needs mapping.sql.list_query.' : prefix ? 'No mappings start with "' + prefix + '".' : 'No mappings.' })));
      PX.clear(pag);
      pag.appendChild(h('span', { text: m.items.length + ' shown' + (m.total !== null ? ' of ' + fmt.n(m.total) + ' mappings' : '') }));
      pag.appendChild(h('div', { class: 'pagination-buttons' },
        h('button', { class: 'btn btn-secondary btn-sm', disabled: cursors.length ? null : true, onclick: function () { cursor = cursors.pop() || ''; reload().then(null, PX.fail); } }, 'Previous'),
        h('button', { class: 'btn btn-secondary btn-sm', disabled: m.next_cursor ? null : true, onclick: function () { cursors.push(cursor); cursor = m.next_cursor; reload().then(null, PX.fail); } }, 'Next')));
    }

    function drawSide() {
      var st = store();
      var def = D.destinations.filter(function (d) { return d.roles.indexOf('default') >= 0; })[0];
      var ranks = D.destinations.filter(function (d) { return d.mapped_identifiers; }).map(function (d) { return [d.id, d.mapped_identifiers]; }).sort(function (a, b) { return b[1] - a[1]; });
      PX.clear(storeTile);
      storeTile.appendChild(PX.tileHead('database', 'Store'));
      storeTile.appendChild(h('dl', { class: 'kv' },
        h('dt', { text: 'Source' }), h('dd', { text: { file: 'File (TSV)', redis: 'Redis', sql: 'SQL' }[st.source] || st.source || 'none' }),
        st.path ? [h('dt', { text: 'Path' }), h('dd', { class: 'mono', text: st.path })] : null,
        h('dt', { text: 'Access' }), h('dd', null, h('span', { class: 'badge ' + (st.writable ? 'badge-success' : 'badge-secondary'), text: st.writable ? 'read-write' : 'read-only' })),
        h('dt', { text: 'Mappings' }), h('dd', { text: st.total !== null ? fmt.n(st.total) : 'not counted' }),
        st.normalize ? [h('dt', { text: 'Normalize' }), h('dd', { text: st.normalize })] : null,
        h('dt', { text: 'Default' }), h('dd', null, def ? h('a', { href: '#/destinations/' + enc(def.id), text: def.id }) : '-')));
      if (ranks.length) {
        storeTile.appendChild(h('div', { class: 'divider' }));
        storeTile.appendChild(ranking(ranks, { colors: true }));
      }
      PX.clear(actions);
      if (st.source) actions.appendChild(h('button', { class: 'btn btn-outline', onclick: function () {
        PX.act(API.request('POST', 'mappings/reload'), 'Mappings reloaded', st.source === 'file' ? 'Read ' + (st.path || 'the mapping file') + ' again.' : 'Login delays released.').then(reload, function () {});
      } }, icon('refresh-cw'), 'Reload store'));
      if (st.writable) {
        actions.appendChild(h('button', { class: 'btn btn-outline', onclick: function () { importDialog(reload); } }, icon('upload'), 'Import'));
        actions.appendChild(h('button', { class: 'btn', onclick: function () { mappingDialog(null, st, reload); } }, icon('plus'), 'Add mapping'));
      }
    }

    PX.page(root, function () { return { mappings: listPath(), destinations: 'destinations' }; }, function () {
      root.appendChild(h('div', { class: 'page' },
        h('div', { class: 'page-header' },
          h('div', null, h('div', { class: 'title-row' }, h('h1', { class: 'page-title', text: 'Mappings' })),
            h('p', { class: 'page-subtitle', text: 'Which destination each identifier is routed to. Identifiers without a mapping go to the default destination.' })),
          actions),
        h('div', { class: 'bento' },
          h('div', { class: 'tile tile-pad span-8' }, PX.tileHead('search', 'Route lookup', 'Shows exactly how a login would be routed, without touching the cache.'),
            h('div', { class: 'lookup' }, lookupIn, h('button', { class: 'btn', onclick: doLookup }, 'Look up')), lookupOut),
          storeTile),
        h('div', { class: 'tile-table' },
          h('div', { class: 'toolbar' },
            h('input', { class: 'input', type: 'search', placeholder: 'Filter by identifier prefix', 'aria-label': 'Prefix', oninput: function (e) {
              prefix = e.target.value;
              clearTimeout(typing);
              typing = setTimeout(function () { cursors = []; cursor = ''; reload().then(null, PX.fail); }, 300);
            } }),
            h('span', { class: 'grow' }),
            h('span', { class: 'tile-sub', text: 'Cursor paginated, 50 per page' })),
          h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
            h('thead', null, h('tr', null, h('th', { text: 'Identifier' }), h('th', { text: 'Destination' }), h('th', { text: '' }))),
            tbody)),
          pag)));
      rows();
      drawSide();
      var q = PX.query.get('lookup');
      if (q) { lookupIn.value = q; doLookup(); }
    });
    API.get('config').then(function (c) { conf = c; if (PX.alive(g) && D.mappings && storeTile.firstChild) drawSide(); }, function () {});
  }, 'mappings');

  PX.route('/cache', function (root) {
    function draw() {
      PX.clear(root);
      var c = D.cache;
      var input = h('input', { class: 'input', type: 'search', placeholder: 'Identifier', 'aria-label': 'Identifier to invalidate' });
      root.appendChild(h('div', { class: 'page' },
        PX.pageHeader('Cache', { text: 'Routing decisions are cached so most logins never touch the mapping store.' }, [
          h('button', { class: 'btn btn-danger', onclick: function () {
            PX.confirm({ title: 'Invalidate the whole cache?', description: 'Every identifier is looked up in the store again on its next login, and all login delays are released. Safe, but expect a burst of store queries.', danger: true, confirm: 'Invalidate all', onConfirm: function () {
              PX.act(API.request('POST', 'cache/invalidate', { json: {} }), 'Cache cleared', 'All entries and login delays dropped.').then(refresh, function () {});
            } });
          } }, icon('trash-2'), 'Invalidate all')]),
        h('div', { class: 'bento' },
          PX.statTile({ icon: 'database', label: 'Entries', value: fmt.n(c.entries), sub: c.max_bytes !== undefined ? 'budget ' + fmt.bytes(c.max_bytes) : 'max ' + fmt.n(c.max_entries) }),
          PX.statTile({ icon: 'gauge', label: 'Hit rate', value: fmt.pct(c.hit_rate_pct), sub: 'since the counters last reset' }),
          PX.statTile({ icon: 'check', label: 'Hits', value: fmt.n(c.hits) }),
          PX.statTile({ icon: 'search', label: 'Misses', value: fmt.n(c.misses) }),
          h('div', { class: 'tile tile-pad span-6' }, PX.tileHead('timer', 'Time to live'),
            h('dl', { class: 'kv' },
              h('dt', { text: 'Positive (mapped)' }), h('dd', { text: fmt.ttl(c.ttl.positive_ms) }),
              h('dt', { text: 'Negative (default)' }), h('dd', { text: fmt.ttl(c.ttl.negative_ms) }),
              h('dt', { text: 'Transient (store error)' }), h('dd', { text: fmt.ttl(c.ttl.transient_ms) })),
            h('p', { class: 'field-help', text: 'Set in [mapping] (positive_ttl, negative_ttl, cache_max_entries or cache_max_bytes). The transient TTL is 5s, or negative_ttl when shorter.' })),
          h('div', { class: 'tile tile-pad span-6' }, PX.tileHead('refresh-cw', 'Invalidate one identifier'),
            h('div', { class: 'lookup' }, input, h('button', { class: 'btn btn-secondary', onclick: function () {
              var v = input.value.trim();
              if (!v) return;
              PX.act(API.request('POST', 'cache/invalidate', { json: { identifier: v } }), 'Entry invalidated', v + ' will be looked up again on its next login.')
                .then(function () { input.value = ''; return refresh(); }, function () {});
            } }, 'Invalidate')),
            h('p', { class: 'field-help', text: 'Also releases a login delay on that identifier. Mapping changes made through this UI invalidate automatically; use this after editing the store directly.' })))));
    }
    var refresh = refresher({ cache: 'cache' }, draw);
    PX.page(root, { cache: 'cache' }, draw);
    PX.poll(5000, function () {
      if (document.activeElement && document.activeElement.type === 'search' && document.activeElement.value) return null;
      return refresh();
    });
  }, 'cache');

  PX.route('/activity', function (root) {
    var kind = '';
    var list = h('div');
    function path() { return 'events' + API.query({ kind: kind }); }
    function draw() {
      PX.clear(list);
      list.appendChild(D.events.items.length ? eventList(newestFirst(D.events)) : emptyNote('No events.'));
    }
    var g = PX.gen();
    function refresh() { return PX.load({ events: path() }).then(function () { if (PX.alive(g)) draw(); }); }
    PX.page(root, function () { return { events: path() }; }, function () {
      root.appendChild(h('div', { class: 'page' },
        PX.pageHeader('Activity', { text: 'Last 512 events since start: admin actions, health transitions, configuration and mapping changes. Kept in memory only.' }),
        h('div', null, h('div', { class: 'tabs-list', role: 'tablist' }, [['', 'All'], ['admin', 'Admin'], ['health', 'Health'], ['config', 'Config'], ['mapping', 'Mappings']].map(function (k) {
          return h('button', { class: 'tab', role: 'tab', 'aria-selected': String(kind === k[0]), onclick: function (e) {
            kind = k[0];
            e.currentTarget.parentNode.querySelectorAll('.tab').forEach(function (t) { t.setAttribute('aria-selected', 'false'); });
            e.currentTarget.setAttribute('aria-selected', 'true');
            refresh().then(null, PX.fail);
          } }, k[1]);
        }))),
        h('div', { class: 'tile tile-pad' }, list)));
      draw();
    });
    PX.poll(5000, refresh);
  }, 'activity');

})();
