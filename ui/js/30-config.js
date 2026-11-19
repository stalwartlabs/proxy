(function () {
  'use strict';
  var PX = window.PX, h = PX.h, icon = PX.icon, D = PX.D, fmt = PX.fmt, API = PX.API, enc = API.enc;

  var NUMERIC = { usize: 1, u16: 1, u32: 1, u64: 1 };
  var DEST_KEYS = { default_destination: 1, smtp_passthrough_destination: 1 };
  var NAME_RE = /^[A-Za-z0-9_-]+$/;

  function loadConfig() {
    var loads = { conf: 'config' };
    if (!D.schema) loads.schema = 'config/schema';
    return loads;
  }

  function section(id) {
    return D.schema.sections.filter(function (s) { return s.id === id; })[0];
  }

  function same(a, b) {
    return JSON.stringify(a === undefined ? null : a) === JSON.stringify(b === undefined ? null : b);
  }

  function lineDiff(a, b) {
    var A = a.split('\n'), B = b.split('\n');
    var p = 0;
    while (p < A.length && p < B.length && A[p] === B[p]) p++;
    var sa = A.length, sb = B.length;
    while (sa > p && sb > p && A[sa - 1] === B[sb - 1]) { sa--; sb--; }
    var mA = A.slice(p, sa), mB = B.slice(p, sb);
    var n = mA.length, m = mB.length;
    var dp = [];
    for (var i = 0; i <= n; i++) dp.push(new Array(m + 1).fill(0));
    for (i = n - 1; i >= 0; i--) for (var j = m - 1; j >= 0; j--) dp[i][j] = mA[i] === mB[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    var ops = [];
    i = 0; j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && mA[i] === mB[j]) { ops.push([' ', mA[i]]); i++; j++; }
      else if (i < n && (j >= m || dp[i + 1][j] >= dp[i][j + 1])) { ops.push(['-', mA[i]]); i++; }
      else { ops.push(['+', mB[j]]); j++; }
    }
    var before = A.slice(Math.max(0, p - 3), p).map(function (l) { return [' ', l]; });
    var after = A.slice(sa, sa + 3).map(function (l) { return [' ', l]; });
    return { start: Math.max(0, p - 3) + 1, ops: before.concat(ops, after), changed: n + m > 0 };
  }

  function diffView(path, a, b) {
    var d = lineDiff(a, b);
    if (!d.changed) return h('div', { class: 'diff' }, h('div', { class: 'ctx', text: 'No changes.' }));
    return h('div', { class: 'diff' },
      h('div', { class: 'hunk', text: '@@ ' + path + ' line ' + d.start + ' @@' }),
      d.ops.map(function (o) { return h('div', { class: o[0] === '+' ? 'add' : o[0] === '-' ? 'del' : 'ctx', text: o[0] + ' ' + o[1] }); }));
  }

  function errorList(errs) {
    return h('ul', { class: 'stack' }, errs.map(function (e) {
      var where = e.path || (e.line ? 'line ' + e.line : 'configuration');
      return h('li', null, h('span', { class: 'badge badge-destructive mono', text: where + (e.path && e.line ? ' (line ' + e.line + ')' : '') }), ' ', e.message);
    }));
  }

  var ALLOW_RE = /admin\.allow\.|reserved by \[admin\]/;

  function writeFailed(e, opts) {
    if (e.status === 422 && e.body && e.body.errors) {
      if (opts.onErrors) opts.onErrors(e.body.errors);
      var blocked = e.body.errors.some(function (x) { return ALLOW_RE.test(x.message); });
      PX.dialog({
        title: 'Validation failed', description: 'Nothing was written. Fix these and try again.',
        body: [blocked ? h('div', { class: 'banner banner-warning' }, icon('lock'), h('div', { class: 'grow' }, h('b', { text: 'Blocked by the operator. ' }), 'The address, host or port is outside [admin.allow] or reserved for the admin listener. [admin] is read-only here; only the configuration file on the host can widen it.')) : null,
          errorList(e.body.errors)],
        footer: function (close) { return [h('button', { class: 'btn', text: 'OK', onclick: close })]; }
      });
    } else if (e.status === 409) {
      if (opts.onConflict) opts.onConflict();
      PX.toast('Configuration changed on disk', 'Another change was saved first. The page was reloaded with the current file.', 'warning');
      PX.render();
    } else {
      PX.fail(e);
    }
  }

  function review(conf, send, opts) {
    send(true).then(function (r) {
      var fresh = r.restart_required.filter(function (k) { return conf.restart_required.indexOf(k) < 0; });
      PX.dialog({
        title: 'Review changes', cls: 'dialog-lg',
        description: 'Dry run passed. Applying writes ' + conf.path + ' atomically (the previous file is kept in the history), then applies it like a reload.',
        body: [
          h('div', { class: 'banner banner-info' }, icon('check'), h('div', { class: 'grow' }, h('b', { text: 'Valid. ' }), 'Revision ' + conf.revision + ' becomes ' + r.revision + '.')),
          fresh.length ? h('div', { class: 'banner banner-warning' }, icon('triangle-alert'), h('div', { class: 'grow' }, h('b', { text: 'Restart required for: ' }), fresh.join(', '), h('p', { text: 'These are saved to the file, but the running proxy keeps its current values until it restarts.' }))) : null,
          diffView(conf.path, conf.source, r.source)
        ],
        footer: function (close) {
          return [h('button', { class: 'btn btn-outline', text: 'Back', onclick: close }),
            h('button', { class: 'btn', onclick: function () {
              close();
              send(false).then(function (done) {
                D.overview = null;
                PX.toast('Saved and applied', 'Revision ' + done.revision + (done.restart_required.length ? '. Restart required for some changes.' : ''), done.restart_required.length ? 'warning' : 'success');
                if (opts.done) opts.done(); else PX.render();
              }, function (e) { writeFailed(e, opts); });
            } }, icon('check'), 'Apply')];
        }
      });
    }, function (e) { writeFailed(e, opts); });
  }

  function dry(flag) {
    return flag ? '?dry_run=true' : '';
  }

  PX.applyOps = function (conf, ops, opts) {
    opts = opts || {};
    if (!ops.length) { PX.toast('No changes', 'Nothing to apply.'); return; }
    review(conf, function (dryRun) {
      return API.request('PATCH', 'config' + dry(dryRun), { json: { revision: conf.revision, ops: ops } });
    }, opts);
  };

  function applySource(conf, text, opts) {
    review(conf, function (dryRun) {
      return API.request('PUT', 'config/source' + dry(dryRun), { text: text, headers: { 'If-Match': '"' + conf.revision + '"' } });
    }, opts || {});
  }

  function restore(conf, id) {
    review(conf, function (dryRun) {
      return API.request('POST', 'config/history/' + enc(id) + '/restore' + dry(dryRun), { json: { revision: conf.revision } });
    }, {});
  }

  function toJson(f, v) {
    if (v === '' || v === null || v === undefined) return null;
    if (NUMERIC[f.type]) return Number(v);
    if (f.type === 'list') {
      var items = v.filter(function (x) { return x !== ''; });
      return items.length || f.default ? items : null;
    }
    return v;
  }

  function fieldControl(f, value, onChange, disabled, conf) {
    var type = f.type;
    if (type === 'bool') {
      var on = value === undefined || value === null ? !!f.default : !!value;
      var t = h('button', { class: 'toggle', type: 'button', role: 'switch', 'aria-checked': String(on), 'aria-label': f.label, disabled: disabled ? true : null, onclick: function () { on = !on; t.setAttribute('aria-checked', String(on)); onChange(on); } });
      return t;
    }
    var options = f.values || (DEST_KEYS[f.key] && conf ? Object.keys(conf.values.destination).sort() : null);
    if (type === 'enum' || options) {
      return h('select', { class: 'select', 'aria-label': f.label, disabled: disabled ? true : null, onchange: function (e) { onChange(e.target.value); } },
        f.required ? null : h('option', { value: '', text: '(not set)' }),
        (options || []).map(function (v) { return h('option', { value: v, selected: v === value ? 'selected' : null, text: v + (f.default === v ? '  (default)' : '') }); }));
    }
    if (type === 'list') {
      var items = (value || []).map(String);
      var wrap = h('div', { class: 'list-editor' });
      var draw = function () {
        PX.clear(wrap);
        items.forEach(function (it, i) {
          wrap.appendChild(h('div', { class: 'list-editor-row' },
            h('input', { class: 'input mono', value: it, disabled: disabled ? true : null, 'aria-label': f.label + ' ' + (i + 1), onchange: function (e) { items[i] = e.target.value.trim(); onChange(items.slice()); } }),
            disabled ? null : h('button', { class: 'btn btn-ghost-danger btn-icon-sm', type: 'button', 'aria-label': 'Remove', onclick: function () { items.splice(i, 1); draw(); onChange(items.slice()); } }, icon('x'))));
        });
        if (!disabled) wrap.appendChild(h('div', null, h('button', { class: 'btn btn-secondary btn-sm', type: 'button', onclick: function () { items.push(''); draw(); var ins = wrap.querySelectorAll('input'); ins[ins.length - 1].focus(); } }, icon('plus'), 'Add')));
      };
      draw();
      return wrap;
    }
    var isNum = !!NUMERIC[type];
    return h('input', {
      class: 'input' + (type === 'socket_addr' ? ' mono' : ''),
      type: type === 'secret' ? 'password' : isNum ? 'number' : 'text',
      min: isNum ? '0' : null,
      value: value === undefined || value === null ? '' : String(value),
      placeholder: f.default !== undefined ? String(f.default) + ' (default)' : '',
      disabled: disabled ? true : null,
      autocomplete: type === 'secret' ? 'off' : null,
      'aria-label': f.label,
      oninput: function (e) { onChange(e.target.value); }
    });
  }

  function editor(conf, readonly) {
    var changes = {};
    var errors = {};
    var bar;
    var ed = {
      count: function () { return Object.keys(changes).length; },
      ops: function () {
        return Object.keys(changes).map(function (k) {
          var c = changes[k];
          return c.value === null ? { op: 'remove', path: c.path } : { op: 'set', path: c.path, value: c.value };
        });
      },
      bar: function (onReview) {
        bar = h('div', { class: 'action-bar-wrap hidden' });
        bar.update = function () {
          var n = ed.count();
          PX.clear(bar);
          bar.classList.toggle('hidden', n === 0);
          bar.appendChild(h('div', { class: 'action-bar' },
            h('span', { class: 'action-bar-dot' }),
            h('span', { class: 'btn btn-ink btn-sm', text: n + ' unsaved change' + (n === 1 ? '' : 's') }),
            h('span', { class: 'action-bar-divider' }),
            h('button', { class: 'btn btn-ink btn-sm', onclick: function () { PX.render(); } }, 'Discard'),
            h('button', { class: 'btn btn-sm', onclick: onReview }, icon('eye'), 'Review and apply')));
        };
        return bar;
      },
      track: function (path, f, initial, v) {
        var key = path.join('\u0000');
        var value = toJson(f, v);
        if (value === null && f.type === 'list' && Array.isArray(initial)) value = [];
        if (same(value, initial)) delete changes[key]; else changes[key] = { path: path, value: value };
        if (bar) bar.update();
      },
      row: function (path, f, initial, opts) {
        opts = opts || {};
        var err = h('p', { class: 'field-error hidden' });
        errors[path.join('.')] = err;
        return h('div', { class: 'field-row', 'data-key': path.join('.') },
          h('div', null,
            h('div', { class: 'field-head' }, h('span', { class: 'field-label', text: f.label }), f.required ? h('span', { class: 'field-required', text: '*' }) : null, f.restart ? h('span', { class: 'badge badge-restart', title: 'Takes effect after a restart', text: 'Restart' }) : null),
            h('div', { class: 'field-help mono', text: path.join('.') }),
            f.help ? h('p', { class: 'field-help', text: f.help }) : null),
          h('div', { class: 'field-ctl' }, fieldControl(f, initial, function (v) { (opts.onChange || ed.track)(path, f, initial, v); }, readonly || opts.readonly, conf), err));
      },
      showErrors: function (errs) {
        Object.keys(errors).forEach(function (k) {
          errors[k].classList.add('hidden');
          errors[k].textContent = '';
        });
        errs.forEach(function (e) {
          var el = errors[e.path];
          if (el) { el.textContent = e.message; el.classList.remove('hidden'); }
        });
      }
    };
    return ed;
  }

  function readonlyBanner(conf) {
    return conf.writable ? null : h('div', { class: 'banner banner-info' }, icon('lock'), h('div', { class: 'grow' }, h('b', { text: 'Read-only. ' }), 'Configuration writes through the API are disabled (admin.config_write = false). Edit ' + conf.path + ' on the host and use Reload from disk.'));
  }

  var ALLOW_LISTS = {
    listener: { intro: 'Listeners may only bind ', keys: [['listener_addresses', 'addresses'], ['listener_ports', 'ports']] },
    destination: { intro: 'Destinations may only point at ', keys: [['destination_hosts', 'hosts'], ['destination_ports', 'ports']] }
  };

  PX.allowBanner = function (conf, kind) {
    var allow = conf.values.admin && conf.values.admin.allow;
    var spec = ALLOW_LISTS[kind];
    var set = allow ? spec.keys.filter(function (k) { return allow[k[0]] && allow[k[0]].length; }) : [];
    if (!set.length) return null;
    return h('div', { class: 'banner banner-info allow-banner' }, icon('lock'), h('div', { class: 'grow' },
      h('b', { text: 'Operator allowlist. ' }), spec.intro,
      set.map(function (k, i) { return [i ? '; ' : '', k[1] + ' ', h('span', { class: 'mono', text: allow[k[0]].join(', ') })]; }),
      '. Set in [admin.allow] on the host; read-only here.'));
  };

  function staleBanner(conf) {
    return conf.revision === conf.running_revision ? null : h('div', { class: 'banner banner-warning' }, icon('triangle-alert'), h('div', { class: 'grow' }, h('b', { text: 'File changed on disk. ' }), conf.path + ' (revision ' + conf.revision + ') differs from the running configuration (revision ' + conf.running_revision + '). Reload from disk to apply it; edits here are based on the file.'));
  }

  function entryForm(root, kind, id) {
    var isNew = !id;
    PX.page(root, loadConfig(), function () {
      var conf = D.conf;
      var sc = section(kind);
      var all = conf.values[kind] || {};
      if (!isNew && !all[id]) { root.appendChild(PX.errorState({ message: 'Unknown ' + kind + ' ' + id })); return; }
      var values = isNew ? {} : all[id];
      var ed = editor(conf, !conf.writable);
      var name = '';
      var nameErr = h('p', { class: 'field-error hidden' });
      var draft = {};
      var protoRows = [];
      var protoState = {};
      var listLink = kind === 'destination' ? '#/destinations' : '#/listeners';
      var plain = sc.fields.filter(function (f) { return f.type !== 'map' && f.type !== 'table'; });
      var protoField = sc.fields.filter(function (f) { return f.key === 'protocol' && f.type === 'map'; })[0];

      function collect(path, f, initial, v) {
        if (isNew) {
          var value = toJson(f, v);
          if (value === null) delete draft[f.key]; else draft[f.key] = value;
          bar.update();
        } else {
          ed.track(path, f, initial, v);
          bar.update();
        }
      }

      var rows = h('div', { class: 'rows' },
        isNew ? h('div', { class: 'field-row' },
          h('div', null, h('div', { class: 'field-head' }, h('span', { class: 'field-label', text: 'Name' }), h('span', { class: 'field-required', text: '*' })),
            h('p', { class: 'field-help', text: 'Used in mappings and routing. Letters, digits, dash and underscore.' })),
          h('div', { class: 'field-ctl' }, h('input', { class: 'input', 'aria-label': 'Name', disabled: conf.writable ? null : true, oninput: function (e) { name = e.target.value.trim(); bar.update(); } }), nameErr)) : null,
        plain.map(function (f) { return ed.row([kind, id || 'new', f.key], f, values[f.key], { onChange: collect }); }));

      var protoTile = null;
      if (protoField) {
        var current = values.protocol || {};
        var sub = {};
        protoField.fields.forEach(function (x) { sub[x.key] = x; });
        protoTile = h('section', { class: 'tile form-section' }, h('h2', { class: 'section-title', text: 'Endpoints' }),
          h('p', { class: 'field-help', text: 'One row per protocol this backend serves. Credential-bearing protocols on a plain leg need allow_plaintext_auth.' }),
          h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
            h('thead', null, h('tr', null, ['Protocol', 'Enabled', 'Port', 'TLS', 'Forwarding override'].map(function (t) { return h('th', { text: t }); }))),
            h('tbody', null, protoField.key_enum.map(function (p) {
              var e = current[p];
              var st = { enabled: !!e, port: e ? e.port : '', tls: e ? e.tls : 'implicit', forwarding: e && e.forwarding ? e.forwarding : '' };
              protoState[p] = st;
              function changed() { bar.update(); }
              var dis = conf.writable ? null : true;
              protoRows.push(p);
              return h('tr', null,
                h('td', { text: fmt.proto(p) }),
                h('td', null, fieldControl({ type: 'bool', label: fmt.proto(p) + ' enabled' }, st.enabled, function (v) { st.enabled = v; changed(); }, !conf.writable)),
                h('td', null, h('input', { class: 'input', type: 'number', min: '1', max: '65535', value: st.port === '' ? '' : String(st.port), disabled: dis, 'aria-label': fmt.proto(p) + ' port', oninput: function (ev) { st.port = ev.target.value === '' ? '' : Number(ev.target.value); changed(); } })),
                h('td', null, fieldControl({ type: 'enum', values: sub.tls.values, required: true, label: fmt.proto(p) + ' TLS' }, st.tls, function (v) { st.tls = v; changed(); }, !conf.writable)),
                h('td', null, fieldControl({ type: 'enum', values: sub.forwarding.values, label: fmt.proto(p) + ' forwarding' }, st.forwarding, function (v) { st.forwarding = v; changed(); }, !conf.writable)));
            })))));
      }

      function protoOps(ops, base) {
        var current = values.protocol || {};
        var obj = {};
        protoRows.forEach(function (p) {
          var st = protoState[p], before = current[p];
          var next = st.enabled ? { port: st.port === '' ? null : st.port, tls: st.tls, forwarding: st.forwarding || null } : null;
          if (next) obj[p] = next;
          if (!base) return;
          var prev = before ? { port: before.port, tls: before.tls, forwarding: before.forwarding || null } : null;
          if (same(prev, next)) return;
          ops.push(next ? { op: 'set', path: base.concat(['protocol', p]), value: next } : { op: 'remove', path: base.concat(['protocol', p]) });
        });
        return obj;
      }

      function pending() {
        if (isNew) return name || Object.keys(draft).length ? 1 : 0;
        var ops = ed.ops();
        protoOps(ops, [kind, id]);
        return ops.length;
      }

      var bar = h('div', { class: 'action-bar-wrap hidden' });
      bar.update = function () {
        var n = pending();
        PX.clear(bar);
        bar.classList.toggle('hidden', n === 0);
        bar.appendChild(h('div', { class: 'action-bar' },
          h('span', { class: 'action-bar-dot' }),
          h('span', { class: 'btn btn-ink btn-sm', text: isNew ? 'New ' + kind : n + ' unsaved change' + (n === 1 ? '' : 's') }),
          h('span', { class: 'action-bar-divider' }),
          h('button', { class: 'btn btn-ink btn-sm', onclick: function () { PX.render(); } }, 'Discard'),
          h('button', { class: 'btn btn-sm', onclick: submit }, icon('eye'), 'Review and apply')));
      };

      function submit() {
        var target = isNew ? name : id;
        var ops;
        if (isNew) {
          if (!NAME_RE.test(name) || all[name]) {
            nameErr.textContent = all[name] ? 'A ' + kind + ' with this name exists.' : 'Letters, digits, dash and underscore only.';
            nameErr.classList.remove('hidden');
            return;
          }
          nameErr.classList.add('hidden');
          var value = Object.assign({}, draft);
          if (protoField) value.protocol = protoOps([], null);
          ops = [{ op: 'set', path: [kind, name], value: value }];
        } else {
          ops = ed.ops();
          protoOps(ops, [kind, id]);
        }
        var prefix = kind + '.' + target + '.';
        PX.applyOps(conf, ops, {
          onErrors: function (errs) {
            ed.showErrors(errs.map(function (e) { return e.path.indexOf(prefix) === 0 ? { path: kind + '.' + (id || 'new') + '.' + e.path.slice(prefix.length), message: e.message } : e; }));
          },
          done: function () { PX.navigate(kind === 'destination' ? '#/destinations/' + enc(target) : '#/listeners'); }
        });
      }

      var title = isNew ? 'New ' + kind : (kind === 'destination' ? 'Edit ' + id : id);
      root.appendChild(h('div', { class: 'page page-narrow' },
        PX.pageHeader(title, { text: isNew ? 'Adds a [' + kind + '.<name>] table to the configuration file.' : 'Changes are written to [' + kind + '.' + id + '] and applied like a reload. Live sessions are not interrupted.' }, null,
          { href: !isNew && kind === 'destination' ? '#/destinations/' + enc(id) : listLink, label: !isNew && kind === 'destination' ? id : kind === 'destination' ? 'Destinations' : 'Listeners' }),
        readonlyBanner(conf),
        staleBanner(conf),
        PX.allowBanner(conf, kind),
        sc.restart ? h('div', { class: 'banner banner-info' }, icon('info'), h('div', { class: 'grow' }, 'Adding or removing a ' + kind + ' takes effect after a restart.')) : null,
        h('section', { class: 'tile form-section' }, h('h2', { class: 'section-title', text: 'General' }), rows),
        protoTile,
        bar));
    });
  }

  PX.destinationForm = function (root, id) { entryForm(root, 'destination', id); };
  PX.listenerForm = function (root, id) { entryForm(root, 'listener', id); };

  function sourceTab(container, conf) {
    var ta = h('textarea', { spellcheck: 'false', 'aria-label': 'Configuration source', readonly: conf.writable ? null : true });
    ta.value = conf.source;
    var gutter = h('div', { class: 'editor-gutter', 'aria-hidden': 'true' });
    var status = h('span', { class: 'tile-sub' });
    function lines() {
      var n = ta.value.split('\n').length;
      var t = '';
      for (var i = 1; i <= n; i++) t += i + '\n';
      gutter.textContent = t;
    }
    ta.addEventListener('input', function () { lines(); status.textContent = ta.value === conf.source ? '' : 'Modified'; });
    ta.addEventListener('scroll', function () { gutter.scrollTop = ta.scrollTop; });
    ta.addEventListener('keydown', function (e) {
      if (e.key === 'Tab' && !ta.readOnly) { e.preventDefault(); ta.setRangeText('  ', ta.selectionStart, ta.selectionEnd, 'end'); lines(); }
    });
    lines();
    function validate() {
      API.request('POST', 'config/validate', { text: ta.value }).then(function () { PX.toast('Valid', 'The configuration passed validation.', 'success'); }, function (e) {
        if (e.status === 422 && e.body && e.body.errors) PX.dialog({ title: 'Invalid configuration', body: errorList(e.body.errors), footer: function (close) { return [h('button', { class: 'btn', text: 'OK', onclick: close })]; } });
        else writeFailed(e, {});
      });
    }
    container.appendChild(h('div', { class: 'stack' },
      h('div', { class: 'toolbar tile' },
        h('span', { class: 'mono', text: conf.path }),
        h('span', { class: 'badge badge-secondary mono', text: conf.revision }),
        status,
        h('span', { class: 'grow' }),
        h('button', { class: 'btn btn-outline btn-sm', onclick: validate }, icon('check'), 'Validate'),
        conf.writable ? h('button', { class: 'btn btn-sm', onclick: function () { applySource(conf, ta.value); } }, icon('save'), 'Save and apply') : null),
      h('p', { class: 'field-help', text: 'Secrets are shown masked. Leaving a masked value unchanged keeps the value on disk. The [admin] table cannot be changed here.' }),
      h('div', { class: 'editor' }, gutter, ta)));
  }

  function historyTab(container, conf) {
    var body = h('div', { class: 'loading' }, icon('refresh-cw'), 'Loading');
    var g = PX.gen();
    container.appendChild(body);
    API.request('GET', 'config/history').then(function (list) {
      if (!PX.alive(g)) return;
      var table = h('div', { class: 'tile-table' }, h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
        h('thead', null, h('tr', null, ['Replaced', 'Revision', 'Size', ''].map(function (t) { return h('th', { text: t }); }))),
        h('tbody', null, list.length ? list.map(function (r) {
          return h('tr', null,
            h('td', null, fmt.time(r.at), h('span', { class: 'sub', text: fmt.ago(r.at) })),
            h('td', null, h('span', { class: 'mono', text: r.revision })),
            h('td', { text: fmt.bytes(r.size) }),
            h('td', { class: 'actions' },
              h('button', { class: 'btn btn-secondary btn-sm', onclick: function () {
                API.request('GET', 'config/history/' + enc(r.id)).then(function (entry) {
                  PX.dialog({ title: 'Revision ' + r.revision, cls: 'dialog-lg', description: 'Changes from this version to the current file.', body: diffView(conf.path, entry.source, conf.source), footer: function (close) { return [h('button', { class: 'btn', text: 'Close', onclick: close })]; } });
                }, PX.fail);
              } }, icon('eye'), 'Diff'), ' ',
              conf.writable ? h('button', { class: 'btn btn-outline btn-sm', onclick: function () { restore(conf, r.id); } }, icon('rotate-ccw'), 'Restore') : null));
        }) : h('tr', null, h('td', { colspan: '4', class: 'table-empty', text: 'No saved versions yet. Every write through the API keeps the file it replaces.' }))))));
      body.replaceWith(h('div', { class: 'stack' }, table,
        h('p', { class: 'field-help', text: 'The last 10 replaced versions are kept in ' + conf.path + '.history/. A change made on disk after the page loaded is detected by its revision and refused until the page is reloaded.' })));
    }, function (e) {
      if (PX.alive(g)) body.replaceWith(PX.errorState(e));
    });
  }

  function tableRows(ed, path, fields, values, readonly) {
    var out = [];
    fields.forEach(function (f) {
      var v = values ? values[f.key] : undefined;
      if (f.type === 'table' || f.type === 'map' || (f.type === 'list' && f.item === 'table')) return;
      out.push(ed.row(path.concat([f.key]), f, v, { readonly: readonly }));
    });
    return out;
  }

  function nested(ed, path, fields, values, readonly) {
    var out = [];
    fields.forEach(function (f) {
      var v = values ? values[f.key] : undefined;
      if (f.type === 'table') {
        out.push(h('section', { class: 'tile form-section' }, h('h2', { class: 'section-title', text: f.label }),
          h('div', { class: 'field-help mono', text: path.concat([f.key]).join('.') }),
          h('div', { class: 'rows' }, tableRows(ed, path.concat([f.key]), f.fields, v, readonly))));
      } else if (f.type === 'map') {
        var keys = Object.keys(v || {}).sort();
        out.push(h('section', { class: 'tile form-section' }, h('h2', { class: 'section-title', text: f.label }),
          keys.length ? keys.map(function (k) {
            return h('div', { class: 'stack' }, h('div', { class: 'field-help mono', text: path.concat([f.key, k]).join('.') }),
              h('div', { class: 'rows' }, tableRows(ed, path.concat([f.key, k]), f.fields, v[k], readonly)));
          }) : h('p', { class: 'field-help', text: 'None configured.' }),
          h('p', { class: 'field-help', text: 'Add or remove entries in the Source tab.' })));
      } else if (f.type === 'list' && f.item === 'table') {
        var items = v || [];
        out.push(h('section', { class: 'tile form-section' }, h('h2', { class: 'section-title', text: f.label + ' (evaluated in order)' }),
          h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
            h('thead', null, h('tr', null, h('th', { text: '#' }), f.fields.map(function (x) { return h('th', { text: x.label }); }))),
            h('tbody', null, items.length ? items.map(function (it, i) {
              return h('tr', null, h('td', { text: String(i + 1) }), f.fields.map(function (x) {
                var c = it[x.key];
                return h('td', { class: 'mono', text: c === null || c === undefined ? '-' : typeof c === 'object' ? JSON.stringify(c) : String(c) });
              }));
            }) : h('tr', null, h('td', { colspan: String(f.fields.length + 1), class: 'table-empty', text: 'None configured.' }))))),
          h('p', { class: 'field-help', text: 'Edit routes in the Source tab.' })));
      }
    });
    return out;
  }

  function sectionsTab(container, conf, active) {
    var tables = D.schema.sections.filter(function (s) { return s.kind === 'table'; });
    var maps = D.schema.sections.filter(function (s) { return s.kind === 'map'; });
    var sc = tables.filter(function (s) { return s.id === active; })[0] || tables[0];
    var readonly = !conf.writable || !!sc.readonly;
    var ed = editor(conf, readonly);
    var values = conf.values[sc.id] || {};
    var bar = ed.bar(function () {
      PX.applyOps(conf, ed.ops(), { onErrors: ed.showErrors });
    });
    var top = tableRows(ed, [sc.id], sc.fields, values, readonly);
    container.appendChild(h('div', { class: 'stack' },
      h('div', { class: 'table-wrap' }, h('div', { class: 'tabs-list', role: 'tablist' },
        tables.map(function (s) { return h('a', { class: 'tab', role: 'tab', href: '#/config?section=' + s.id, 'aria-selected': String(s.id === sc.id) }, s.label); }),
        maps.map(function (s) { return h('a', { class: 'tab', role: 'tab', href: s.id === 'destination' ? '#/destinations' : '#/listeners' }, s.label, icon('chevron-right', 'icon-sm')); }))),
      sc.readonly ? h('div', { class: 'banner banner-info' }, icon('lock'), h('div', { class: 'grow' }, 'The [' + sc.id + '] table is read-only through the API, so an edit here can never lock administrators out.')) : null,
      top.length ? h('section', { class: 'tile form-section' }, h('div', { class: 'rows' }, top)) : null,
      nested(ed, [sc.id], sc.fields, values, readonly),
      bar));
  }

  var MAX_PEM = 128 * 1024;
  var CERT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

  function pemField(label, placeholder, secret) {
    var area = h('textarea', { class: 'textarea mono', rows: '6', spellcheck: 'false', autocomplete: 'off', placeholder: placeholder, 'aria-label': label });
    var file = h('input', { class: 'hidden', type: 'file', accept: '.pem,.crt,.cer,.key,text/plain', 'aria-label': label + ' file' });
    file.addEventListener('change', function () {
      var f = file.files && file.files[0];
      file.value = '';
      if (!f) return;
      if (f.size > MAX_PEM) { PX.toast('File too large', label + ' files are limited to 128 KB.', 'destructive'); return; }
      f.text().then(function (text) { area.value = text; area.removeAttribute('aria-invalid'); }, PX.fail);
    });
    var wrap = h('div', { class: 'field' },
      h('div', { class: 'field-head' }, h('span', { class: 'field-label', text: label }), h('span', { class: 'grow' }),
        h('button', { class: 'btn btn-secondary btn-sm', type: 'button', onclick: function () { file.click(); } }, icon('upload'), 'Choose file')),
      area, file, secret ? h('p', { class: 'field-help', text: 'Sent once over this TLS session, stored by the proxy with owner-only permissions and never shown again.' }) : null);
    return { el: wrap, area: area };
  }

  function uploadDialog(conf, presetId) {
    var all = (conf.values.tls && conf.values.tls.certificate) || {};
    var idInput = h('input', { class: 'input mono', value: presetId || '', placeholder: 'mail', 'aria-label': 'Certificate name', disabled: presetId ? true : null });
    var cert = pemField('Certificate chain (PEM)', '-----BEGIN CERTIFICATE-----', false);
    var key = pemField('Private key (PEM)', '-----BEGIN PRIVATE KEY-----', true);
    var current = (presetId && all[presetId]) || {};
    var subjects = h('input', { class: 'input mono', value: (current.subjects || []).join(', '), placeholder: 'mail.example.com, *.example.com', 'aria-label': 'Subjects' });
    var adminNote = h('div', { class: 'banner banner-warning' }, icon('triangle-alert'), h('div', { class: 'grow' }, h('b', { text: 'This replaces the admin UI certificate. ' }), 'The admin listener serves the certificate named admin; after applying, your browser asks you to trust the new one. Without an admin entry the admin UI uses the default certificate, or a generated self-signed one whose fingerprint changes on every apply or restart.'));
    function noteAdmin() { adminNote.classList.toggle('hidden', idInput.value.trim() !== 'admin'); }
    idInput.addEventListener('input', noteAdmin);
    noteAdmin();
    var isDefault = Object.keys(all).length === 0 || current.default;
    var toggle = fieldControl({ type: 'bool', label: 'Default certificate' }, !!isDefault, function (v) { isDefault = v; }, false, conf);
    var closeUpload = PX.dialog({
      title: presetId ? 'Replace certificate ' + presetId : 'Add TLS certificate',
      cls: 'dialog-lg',
      onClose: function () { key.area.value = ''; },
      description: 'Paste or choose PEM files. The proxy checks that the key matches the certificate, stores both next to its configuration and references them in [tls.certificate].',
      body: [
        h('label', { class: 'field' }, h('span', { class: 'field-label', text: 'Name' }), idInput),
        adminNote,
        cert.el, key.el,
        h('label', { class: 'field' }, h('span', { class: 'field-label', text: 'Subjects (optional)' }), subjects, h('p', { class: 'field-help', text: 'Comma separated host names. Empty uses the names in the certificate.' })),
        h('div', { class: 'field' }, h('div', { class: 'field-head' }, h('span', { class: 'field-label', text: 'Default certificate' })), toggle, h('p', { class: 'field-help', text: 'Served on mail and HTTP listeners to clients that send no or an unknown server name. The admin UI always uses the certificate named admin.' }))
      ],
      footer: function (close) {
        return [h('button', { class: 'btn btn-outline', text: 'Cancel', onclick: close }),
          h('button', { class: 'btn', onclick: submit }, icon('upload'), 'Review')];
      }
    });
    function submit() {
      var id = idInput.value.trim();
      var bad = false;
      [[idInput, CERT_ID_RE.test(id)], [cert.area, cert.area.value.indexOf('-----BEGIN ') >= 0], [key.area, key.area.value.indexOf('-----BEGIN ') >= 0]].forEach(function (c) {
        if (c[1]) c[0].removeAttribute('aria-invalid'); else { c[0].setAttribute('aria-invalid', 'true'); bad = true; }
      });
      if (bad) return;
      var list = subjects.value.split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x !== ''; });
      var body = { revision: conf.revision, cert: cert.area.value, key: key.area.value, subjects: list, default: !!isDefault };
      review(conf, function (dryRun) {
        return API.request('PUT', 'certificates/' + enc(id) + dry(dryRun), { json: body });
      }, { done: function () { body.key = ''; closeUpload(); PX.render(); }, onConflict: function () { body.key = ''; closeUpload(); } });
    }
  }

  function certificatesTab(container, conf) {
    var all = (conf.values.tls && conf.values.tls.certificate) || {};
    var ids = Object.keys(all).sort();
    container.appendChild(h('div', { class: 'stack' },
      h('div', { class: 'tile-table' },
        h('div', { class: 'tile-pad' }, PX.tileHead('shield-check', 'TLS certificates', 'Served on implicit TLS and STARTTLS listeners, chosen by server name. The certificate named admin is the one this admin UI uses.',
          conf.writable ? h('button', { class: 'btn btn-sm', onclick: function () { uploadDialog(conf); } }, icon('plus'), 'Add certificate') : null)),
        h('div', { class: 'table-wrap' }, h('table', { class: 'table' },
          h('thead', null, h('tr', null, ['Name', 'Files', 'Subjects', 'Default', ''].map(function (t) { return h('th', { text: t }); }))),
          h('tbody', null, ids.length ? ids.map(function (id) {
            var c = all[id];
            return h('tr', null,
              h('td', null, h('span', { class: 'mono', text: id }), id === 'admin' ? h('span', { class: 'sub', text: 'Serves this admin UI. If removed, the admin UI uses the default certificate, or a generated self-signed one; its fingerprint will change.' }) : null),
              h('td', null, h('span', { class: 'mono', text: c.cert }), h('span', { class: 'sub mono', text: c.key })),
              h('td', null, c.subjects && c.subjects.length ? h('span', { class: 'mono', text: c.subjects.join(', ') }) : h('span', { class: 'text-dim', text: 'from certificate' })),
              h('td', null, c.default ? h('span', { class: 'badge badge-secondary', text: 'default' }) : h('span', { class: 'text-dim', text: '-' })),
              h('td', { class: 'num' }, conf.writable ? h('button', { class: 'btn btn-secondary btn-sm', onclick: function () { uploadDialog(conf, id); } }, icon('upload'), 'Replace') : null));
          }) : h('tr', null, h('td', { colspan: '5', class: 'table-empty', text: 'No certificates. Add one before creating TLS listeners.' }))))))));
  }

  PX.route('/config', function (root) {
    var tab = PX.query.get('tab') || 'sections';
    PX.page(root, loadConfig(), function () {
      var conf = D.conf;
      var body = h('div');
      function tabLink(id, label, ic) {
        return h('a', { class: 'tab', role: 'tab', href: '#/config?tab=' + id, 'aria-selected': String(tab === id) }, icon(ic, 'icon-sm'), label);
      }
      root.appendChild(h('div', { class: 'page' },
        PX.pageHeader('Configuration', { text: conf.path + ', revision ' + conf.revision + ', loaded ' + fmt.ago(conf.loaded_at) }, [
          h('button', { class: 'btn btn-outline', onclick: function () {
            PX.act(API.request('POST', 'config/reload'), 'Reloaded from disk', function (r) { return 'Revision ' + r.revision + ' is running' + (r.restart_required.length ? '. Restart required for some changes.' : '.'); })
              .then(function () { D.overview = null; PX.render(); }, function () {});
          } }, icon('refresh-cw'), 'Reload from disk')]),
        conf.restart_required.length ? h('div', { class: 'banner banner-warning' }, icon('triangle-alert'), h('div', { class: 'grow' }, h('b', { text: 'Restart required. ' }), 'Saved but not yet active: ' + conf.restart_required.join(', ') + '.')) : null,
        staleBanner(conf),
        readonlyBanner(conf),
        h('div', null, h('div', { class: 'tabs-list', role: 'tablist' }, tabLink('sections', 'Sections', 'list-filter'), tabLink('certificates', 'Certificates', 'shield-check'), tabLink('source', 'Source', 'file-code'), tabLink('history', 'History', 'history'))),
        body));
      if (tab === 'source') sourceTab(body, conf);
      else if (tab === 'certificates') certificatesTab(body, conf);
      else if (tab === 'history') historyTab(body, conf);
      else sectionsTab(body, conf, PX.query.get('section'));
    });
  }, 'config');
})();
