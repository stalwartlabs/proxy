window.PX_API = (function () {
  var BASE = '/api/v1/';
  var csrf = null;
  var inflight = {};
  var handlers = { unauthorized: null };

  function enc(segment) {
    return encodeURIComponent(segment);
  }

  function query(params) {
    var parts = [];
    Object.keys(params || {}).forEach(function (k) {
      var v = params[k];
      if (v !== undefined && v !== null && v !== '') parts.push(enc(k) + '=' + enc(String(v)));
    });
    return parts.length ? '?' + parts.join('&') : '';
  }

  function failure(res, data, path) {
    var detail = data && data.error ? data.error : null;
    var err = new Error(res.status === 429 ? 'Too many failed attempts from this address. Try again later.' : detail ? detail.message : 'HTTP ' + res.status);
    err.status = res.status;
    err.code = detail ? detail.code : null;
    err.body = data;
    if (res.status === 401 && path !== 'session' && handlers.unauthorized) handlers.unauthorized();
    return err;
  }

  function request(method, path, opts) {
    opts = opts || {};
    var headers = { Accept: 'application/json' };
    var body;
    if (opts.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(opts.json);
    } else if (opts.text !== undefined) {
      headers['Content-Type'] = 'application/toml';
      body = opts.text;
    }
    if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
    if (opts.headers) Object.keys(opts.headers).forEach(function (k) { headers[k] = opts.headers[k]; });
    return fetch(BASE + path, { method: method, headers: headers, body: body, credentials: 'same-origin', cache: 'no-store' }).then(function (res) {
      if (res.status === 204) return null;
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try { data = JSON.parse(text); } catch (e) { data = null; }
        }
        if (res.ok) return data;
        throw failure(res, data, path);
      });
    }, function () {
      var err = new Error('The proxy could not be reached');
      err.status = 0;
      throw err;
    });
  }

  function get(path) {
    if (inflight[path]) return inflight[path];
    var p = request('GET', path);
    inflight[path] = p;
    function done() { delete inflight[path]; }
    p.then(done, done);
    return p;
  }

  return {
    enc: enc,
    query: query,
    request: request,
    get: get,
    setCsrf: function (token) { csrf = token; },
    onUnauthorized: function (fn) { handlers.unauthorized = fn; }
  };
})();
