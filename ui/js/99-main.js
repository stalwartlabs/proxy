(function () {
  'use strict';
  var PX = window.PX, h = PX.h, icon = PX.icon, D = PX.D, API = PX.API;

  function setSession(view) {
    PX.session = view;
    API.setCsrf(view ? view.csrf : null);
  }

  API.onUnauthorized(function () {
    if (!PX.session) return;
    setSession(null);
    var full = (location.hash || '#/').slice(1) || '/';
    PX.afterLogin = full === '/login' ? null : full;
    PX.toast('Signed out', 'The session expired. Sign in again to continue.');
    PX.navigate('#/login');
  });

  var forced = location.search.match(/[?&]theme=(light|dark)/);
  if (forced) document.documentElement.setAttribute('data-theme', forced[1]);

  var NAV = [
    { group: null, items: [{ id: 'overview', label: 'Overview', icon: 'layout-dashboard', href: '#/' }] },
    { group: 'Traffic', items: [
      { id: 'destinations', label: 'Destinations', icon: 'server', href: '#/destinations', alert: function () { var c = D.overview && D.overview.destinations; return !!c && c.up < c.total; } },
      { id: 'listeners', label: 'Listeners', icon: 'radio-tower', href: '#/listeners' },
      { id: 'connections', label: 'Connections', icon: 'cable', href: '#/connections', count: function () { return D.overview ? D.overview.sessions.active : null; } }
    ] },
    { group: 'Routing', items: [
      { id: 'mappings', label: 'Mappings', icon: 'route', href: '#/mappings' },
      { id: 'cache', label: 'Cache', icon: 'database', href: '#/cache' }
    ] },
    { group: 'System', items: [
      { id: 'config', label: 'Configuration', icon: 'settings', href: '#/config' },
      { id: 'activity', label: 'Activity', icon: 'history', href: '#/activity' }
    ] }
  ];

  var sidebarOpen = window.matchMedia('(min-width: 48rem)').matches;

  function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('proxy-ui-theme', t); } catch (e) {}
  }

  function themeButton() {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    return h('button', { class: 'btn btn-ghost btn-icon', 'aria-label': 'Toggle theme', title: 'Toggle theme', onclick: function () {
      setTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
      PX.render();
    } }, icon(dark ? 'sun' : 'moon'));
  }

  function logout() {
    API.request('DELETE', 'session').then(null, function () {}).then(function () {
      setSession(null);
      D.overview = null;
      PX.toast('Signed out', 'The session was ended on the server.');
      PX.navigate('#/login');
    });
  }

  function userMenu() {
    var close = PX.dialog({ bare: true, cls: 'popover user-menu', body: [
      h('div', { class: 'user-menu-head' }, h('b', { text: 'Administrator' }), 'Browser session', h('br'), 'Idle timeout ' + PX.fmt.dur(PX.session.idle_timeout_s) + ', expires in ' + PX.fmt.left(PX.session.expires_at)),
      h('div', { class: 'menu-separator' }),
      h('button', { class: 'menu-item', onclick: function () { close(); PX.navigate('#/activity'); } }, icon('history'), 'Activity log'),
      h('button', { class: 'menu-item', onclick: function () { close(); PX.navigate('#/config'); } }, icon('settings'), 'Configuration'),
      h('div', { class: 'menu-separator' }),
      h('button', { class: 'menu-item', onclick: function () { close(); logout(); } }, icon('log-out'), 'Sign out')
    ] });
  }

  function palette() {
    var input = h('input', { class: 'input', placeholder: 'Jump to a page, destination, listener or identifier...', 'aria-label': 'Search' });
    var list = h('div', { class: 'palette-list', role: 'listbox' });
    var close;
    var entries = [];
    NAV.forEach(function (g) { g.items.forEach(function (it) { entries.push({ label: it.label, hint: 'Page', icon: it.icon, href: it.href }); }); });
    function addAll() {
      D.destinations.forEach(function (d) { entries.push({ label: d.id, hint: 'Destination', icon: 'server', href: '#/destinations/' + encodeURIComponent(d.id) }); });
      D.listeners.forEach(function (l) { entries.push({ label: l.id, hint: 'Listener', icon: 'radio-tower', href: '#/listeners/' + encodeURIComponent(l.id) }); });
    }
    addAll();
    if (!D.destinations.length || !D.listeners.length) {
      PX.load({ destinations: 'destinations', listeners: 'listeners' }).then(function () {
        entries = entries.filter(function (e) { return e.hint === 'Page'; });
        addAll();
        draw();
      }, function () {});
    }
    function draw() {
      var q = input.value.trim().toLowerCase();
      PX.clear(list);
      var hits = entries.filter(function (e) { return !q || e.label.toLowerCase().indexOf(q) >= 0; }).slice(0, 9);
      if (q.indexOf('@') > 0 || q.length > 2) {
        hits.push({ label: 'Look up routing for "' + input.value.trim() + '"', hint: 'Mappings', icon: 'search', href: '#/mappings?lookup=' + encodeURIComponent(input.value.trim()) });
      }
      if (!hits.length) list.appendChild(h('div', { class: 'palette-empty', text: 'No matches' }));
      hits.forEach(function (e, i) {
        list.appendChild(h('a', { class: 'menu-item' + (i === 0 ? ' is-focused' : ''), href: e.href, onclick: function () { close(); } }, icon(e.icon), e.label, h('small', { text: e.hint })));
      });
    }
    input.addEventListener('input', draw);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        var f = list.querySelector('a');
        if (f) { close(); location.hash = f.getAttribute('href'); }
      }
    });
    close = PX.dialog({ bare: true, cls: 'palette', body: [input, list] });
    draw();
  }

  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k' && PX.session) {
      e.preventDefault();
      palette();
    }
  });

  function topbar() {
    return h('header', { class: 'topbar' },
      h('button', { class: 'btn btn-ghost btn-icon menu-toggle', 'aria-label': 'Menu', onclick: function () { sidebarOpen = !sidebarOpen; PX.render(); } }, icon('menu')),
      h('a', { class: 'topbar-brand', href: '#/', 'aria-label': 'Overview' }, PX.logo()),
      h('div', { class: 'topbar-search' },
        h('button', { class: 'topbar-search-btn', onclick: palette }, icon('search'), h('span', { text: 'Search destinations, listeners, identifiers' }), h('kbd', { class: 'kbd', text: 'Ctrl K' }))),
      h('div', { class: 'topbar-actions' },
        h('button', { class: 'btn btn-ghost btn-icon topbar-search-icon', 'aria-label': 'Search', onclick: palette }, icon('search')),
        themeButton(),
        h('button', { class: 'btn btn-outline btn-icon-lg', 'aria-label': 'Session menu', onclick: userMenu }, icon('user'))));
  }

  function sidebar(active) {
    var nav = h('nav', { class: 'sidebar-nav', 'aria-label': 'Main' });
    NAV.forEach(function (g) {
      if (g.group) nav.appendChild(h('div', { class: 'nav-group', text: g.group }));
      g.items.forEach(function (it) {
        var extra = null;
        var n = it.count ? it.count() : null;
        if (n !== null) extra = h('span', { class: 'badge-count', text: String(n) });
        if (it.alert && it.alert()) extra = h('span', { class: 'nav-alert', title: 'Attention needed' });
        nav.appendChild(h('a', { class: 'nav-item', href: it.href, 'aria-current': active === it.id ? 'page' : null, onclick: function () {
          if (!window.matchMedia('(min-width: 48rem)').matches) sidebarOpen = false;
        } }, icon(it.icon), h('span', { text: it.label }), extra));
      });
    });
    var o = D.overview;
    return h('aside', { class: 'sidebar', hidden: sidebarOpen ? null : 'hidden' },
      h('div', { class: 'sidebar-scroll' }, nav),
      h('div', { class: 'sidebar-foot' },
        h('span', null, 'Stalwart Proxy' + (o ? ' ' + o.version : '')),
        h('span', null, location.hostname + (o ? ', up ' + PX.fmt.dur(o.uptime_s) : ''))));
  }

  var activeNav = null;

  function refreshShell() {
    return PX.load({ overview: 'overview' }).then(function () {
      var old = document.querySelector('.sidebar');
      if (old) old.replaceWith(sidebar(activeNav));
    });
  }

  PX.shell = function (active, renderPage) {
    var root = PX.clear(document.getElementById('root'));
    if (active === 'login') {
      renderPage(root);
      return;
    }
    var content = h('main', { class: 'content', id: 'main' });
    var app = h('div', { class: 'app' + (sidebarOpen ? ' has-sidebar' : '') },
      topbar(),
      h('div', { class: 'app-body' },
        sidebar(active),
        sidebarOpen ? h('div', { class: 'sidebar-backdrop', onclick: function () { sidebarOpen = false; PX.render(); } }) : null,
        content));
    root.appendChild(app);
    renderPage(content);
    window.scrollTo(0, 0);
    activeNav = active;
    if (!D.overview) refreshShell().then(null, function () {});
    PX.poll(5000, refreshShell);
  };

  PX.route('/login', function (root) {
    var input = h('input', { class: 'input input-lg', type: 'password', id: 'token', autocomplete: 'current-password', placeholder: 'Admin token', 'aria-label': 'Admin token' });
    var err = h('p', { class: 'field-error hidden', role: 'alert' });
    var btn = h('button', { class: 'btn btn-lg btn-block', type: 'submit' }, 'Sign in');
    var form = h('form', { class: 'login-form', onsubmit: function (e) {
      e.preventDefault();
      var v = input.value.trim();
      if (!v) { input.setAttribute('aria-invalid', 'true'); return; }
      btn.disabled = true;
      API.request('POST', 'session', { json: { token: v } }).then(function (view) {
        input.value = '';
        setSession(view);
        D.overview = null;
        var dest = PX.afterLogin && PX.afterLogin !== '/login' ? PX.afterLogin : '/';
        PX.afterLogin = null;
        PX.navigate('#' + dest);
      }, function (e2) {
        btn.disabled = false;
        input.setAttribute('aria-invalid', 'true');
        err.textContent = e2.status === 401 ? 'Invalid token. Repeated failures lock this address out for a while.' : e2.status === 429 ? 'Too many failed attempts from this address. Try again later.' : e2.message;
        err.classList.remove('hidden');
      });
    } },
      h('div', { class: 'login-head' }, h('h1', { class: 'page-title', text: 'Proxy administration' }), h('p', { class: 'text-muted', text: 'Sign in with the admin token configured in [admin].' })),
      input, err, btn,
      h('div', { class: 'login-note' }, PX.icon('lock'), h('span', { text: 'TLS connection to the admin listener. The token is exchanged for a short-lived HttpOnly session cookie and is never stored by this page.' })));
    root.appendChild(h('div', { class: 'login' },
      h('div', { class: 'login-glow' }),
      h('div', { class: 'login-card' }, h('div', { class: 'login-logo' }, PX.logo()), form),
      h('div', { class: 'login-theme' }, themeButton())));
    setTimeout(function () { input.focus(); }, 0);
  }, 'login');

  window.addEventListener('hashchange', PX.render);
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden && PX.session) refreshShell().then(null, function () {});
  });

  function start() {
    PX.render();
    API.request('GET', 'session').then(setSession, function () { setSession(null); }).then(PX.render);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
