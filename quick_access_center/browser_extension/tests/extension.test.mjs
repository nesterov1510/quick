import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import vm from 'node:vm';

const read = name => readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
const TARGET = 'https://msb-activity.meryosab.com/login';
const CRM = 'https://crm.example.com/login';
const PANEL = 'https://quick.example.com';
const fakeUser = 'test-user';
const fakePassword = 'not-a-real-password';
const originPattern = url => `${new URL(url).origin}/*`;
const tick = () => new Promise(resolve => setImmediate(resolve));

function backgroundHarness({localSites = null, granted = [originPattern(TARGET)]} = {}) {
  const local = new Map([['panelOrigin', PANEL]]);
  const session = new Map();
  const alarms = new Map();
  const tabs = new Map();
  const handlers = {};
  const recorded = {scripts: [], unregistrations: 0};
  const grantedOrigins = new Set(granted);
  let tabId = 100;
  const area = map => ({
    async get(key) {return {[key]: map.get(key)};},
    async set(values) {for (const [key, value] of Object.entries(values)) map.set(key, value);},
    async remove(key) {map.delete(key);}
  });
  async function fetch(url) {
    if (url.endsWith('sites.local.json')) {
      return localSites
        ? {ok: true, async json() {return {sites: localSites};}}
        : {ok: false, async json() {return {};}};
    }
    return {ok: true, async json() {return JSON.parse(read('sites.json'));}};
  }
  const chrome = {
    runtime: {
      id: 'quick-extension',
      getURL: name => `chrome-extension://quick-extension/${name}`,
      onMessage: {addListener(fn) {handlers.message = fn;}},
      onInstalled: {addListener(fn) {handlers.installed = fn;}},
      onStartup: {addListener(fn) {handlers.startup = fn;}}
    },
    storage: {local: area(local), session: area(session)},
    permissions: {async contains({origins}) {return origins.every(origin => grantedOrigins.has(origin));}},
    scripting: {
      async getRegisteredContentScripts() {return recorded.scripts.map(script => ({id: script.id}));},
      async registerContentScripts(scripts) {recorded.scripts.push(...scripts);},
      async unregisterContentScripts() {recorded.unregistrations += 1;}
    },
    alarms: {
      async create(name, info) {alarms.set(name, info);},
      async clear(name) {alarms.delete(name);},
      onAlarm: {addListener(fn) {handlers.alarm = fn;}}
    },
    tabs: {
      async create(info) {const tab = {id: ++tabId, ...info}; tabs.set(tab.id, tab); return tab;},
      async update(id, info) {Object.assign(tabs.get(id), info); return tabs.get(id);},
      async remove(id) {tabs.delete(id);},
      onRemoved: {addListener(fn) {handlers.removed = fn;}}
    }
  };
  vm.runInNewContext(read('background.js'), {chrome, URL, Date, fetch});
  function send(message, sender) {
    return new Promise(resolve => {
      if (handlers.message(message, sender, resolve) !== true) resolve(undefined);
    });
  }
  return {local, session, alarms, tabs, handlers, recorded, send, nextTabId: () => tabId};
}

const sender = (url, id = 1) => ({id: 'quick-extension', frameId: 0, tab: {id}, url});
const popupSender = {id: 'quick-extension', url: 'chrome-extension://quick-extension/popup.html'};
const request = (login_url = TARGET) =>
  ({type: 'OPEN_LOGIN', login_url, username: fakeUser, password: fakePassword});

test('background accepts only the configured panel and a pinned HTTPS target', async () => {
  const bg = backgroundHarness();
  assert.equal((await bg.send(request(), sender('https://quick.example.com.evil.test/'))).ok, false);
  assert.equal((await bg.send(request(), sender(PANEL + '/vault/'))).ok, false);
  assert.equal((await bg.send(request(), {...sender(PANEL + '/'), id: 'other-extension'})).ok, false);
  assert.equal((await bg.send({...request(), login_url: 'https://evil.test/login'}, sender(PANEL + '/'))).ok, false);
  assert.equal(bg.tabs.size, 0);
  assert.equal((await bg.send(request(), sender(PANEL + '/?category=x'))).ok, true);
  assert.equal(bg.tabs.get(bg.nextTabId()).url, TARGET);
  assert.deepEqual([...bg.local.keys()], ['panelOrigin']); // never store passwords on disk
  assert.equal(bg.session.size, 1); // only in expiring, memory-only session storage
});

test('background releases a credential once, only in the newly opened target tab', async () => {
  const bg = backgroundHarness();
  assert.equal((await bg.send(request(), sender(PANEL + '/'))).ok, true);
  const id = bg.nextTabId();
  assert.equal((await bg.send({type: 'TAKE_LOGIN'}, sender(TARGET, id + 1))).ok, false);
  assert.equal((await bg.send({type: 'TAKE_LOGIN'}, sender('https://phishing.test/login', id))).ok, false);
  assert.equal((await bg.send({type: 'TAKE_LOGIN'}, sender(TARGET + '?redirect=x', id))).ok, false);
  const result = await bg.send({type: 'TAKE_LOGIN'}, sender(TARGET, id));
  assert.equal(result.ok, true);
  assert.equal(result.username, fakeUser);
  assert.equal(result.password, fakePassword);
  assert.equal(bg.session.size, 0);
  assert.equal(bg.alarms.size, 0);
  assert.equal((await bg.send({type: 'TAKE_LOGIN'}, sender(TARGET, id))).ok, false);
});

test('simultaneous requests from one tab cannot both consume the pending password', async () => {
  const bg = backgroundHarness();
  await bg.send(request(), sender(PANEL + '/'));
  const tab = sender(TARGET, bg.nextTabId());
  const attempts = await Promise.all([
    bg.send({type: 'TAKE_LOGIN'}, tab), bg.send({type: 'TAKE_LOGIN'}, tab)
  ]);
  assert.deepEqual(attempts.map(item => item.ok).sort(), [false, true]);
  assert.equal(bg.session.size, 0);
});

test('expired and abandoned credentials are deleted without opening a login session', async () => {
  const bg = backgroundHarness();
  await bg.send(request(), sender(PANEL + '/'));
  const id = bg.nextTabId();
  const key = `pending-login:${id}`;
  bg.session.get(key).expiresAt = Date.now() - 1;
  assert.equal((await bg.send({type: 'TAKE_LOGIN'}, sender(TARGET, id))).ok, false);
  assert.equal(bg.session.size, 0);
  await bg.send(request(), sender(PANEL + '/'));
  const alarmKey = `pending-login:${bg.nextTabId()}`;
  bg.handlers.alarm({name: alarmKey});
  assert.equal(bg.session.size, 0);
  await bg.send(request(), sender(PANEL + '/'));
  bg.handlers.removed(bg.nextTabId());
  assert.equal(bg.session.size, 0);
});

test('a service added to sites.local.json is filled, anything else is refused', async () => {
  const bg = backgroundHarness({
    localSites: [{name: 'CRM', login_url: CRM}],
    granted: [originPattern(TARGET), originPattern(CRM)]
  });
  assert.equal((await bg.send(request(CRM), sender(PANEL + '/'))).ok, true);
  const id = bg.nextTabId();
  assert.equal(bg.tabs.get(id).url, CRM);
  const credential = await bg.send({type: 'TAKE_LOGIN'}, sender(CRM, id));
  assert.equal(credential.ok, true);
  assert.equal(credential.password, fakePassword);

  for (const impostor of [
    'https://crm.example.com/login?next=x', 'https://crm.example.com.evil.test/login',
    'http://crm.example.com/login', 'https://crm.example.com/profile', 'https://other.example.com/login'
  ]) {
    assert.equal((await bg.send(request(impostor), sender(PANEL + '/'))).ok, false, impostor);
  }
  assert.equal(bg.tabs.size, 1);
});

test('a configured service without host permission is reported, not opened', async () => {
  const bg = backgroundHarness({localSites: [{name: 'CRM', login_url: CRM}]});
  const result = await bg.send(request(CRM), sender(PANEL + '/'));
  assert.equal(result.ok, false);
  assert.equal(result.error, 'no_host_permission');
  assert.equal(bg.tabs.size, 0);
  assert.equal(bg.session.size, 0);
});

test('a broken sites.local.json leaves only the reviewed built-in target', async () => {
  const bg = backgroundHarness({localSites: 'not-a-list'});
  assert.equal((await bg.send(request(CRM), sender(PANEL + '/'))).ok, false);
  assert.equal((await bg.send(request(TARGET), sender(PANEL + '/'))).ok, true);
});

test('the login content script is registered only for permitted exact login pages', async () => {
  const bg = backgroundHarness({
    localSites: [{name: 'CRM', login_url: CRM}, {name: 'Root', login_url: 'https://hr.example.org/'}],
    granted: [originPattern(TARGET), originPattern(CRM)]
  });
  await tick();
  const result = await bg.send({type: 'REGISTER_TARGETS'}, popupSender);
  assert.equal(result.ok, true);
  assert.deepEqual([...bg.recorded.scripts.at(-1).matches].sort(), [
    'https://crm.example.com/login',
    'https://crm.example.com/login/',
    'https://msb-activity.meryosab.com/login',
    'https://msb-activity.meryosab.com/login/'
  ]);
  assert.equal(bg.recorded.scripts.at(-1).js[0], 'target.js');
  assert.equal((await bg.send({type: 'REGISTER_TARGETS'}, sender(PANEL + '/'))).ok, false);
});

test('a private HTTP service works only with an explicit opt-in on both sides', async () => {
  const LAN = 'http://192.168.8.99:8085/login';
  const optedIn = backgroundHarness({
    localSites: [{name: 'LAN', login_url: LAN, allow_insecure: true}],
    granted: [originPattern(TARGET), 'http://192.168.8.99/*']
  });
  assert.equal((await optedIn.send(request(LAN), sender(PANEL + '/'))).ok, true);
  assert.equal(optedIn.tabs.get(optedIn.nextTabId()).url, LAN);

  const notOptedIn = backgroundHarness({
    localSites: [{name: 'LAN', login_url: LAN}],
    granted: [originPattern(TARGET), 'http://192.168.8.99/*']
  });
  assert.equal((await notOptedIn.send(request(LAN), sender(PANEL + '/'))).ok, false);

  for (const entry of [
    {name: 'LAN', login_url: 'http://8.8.8.8/login', allow_insecure: true},
    {name: 'LAN', login_url: 'http://intranet.local/login', allow_insecure: true},
    {name: 'LAN', login_url: 'http://169.254.10.4/login', allow_insecure: true}
  ]) {
    const bg = backgroundHarness({localSites: [entry], granted: ['http://*/*']});
    assert.equal((await bg.send(request(entry.login_url), sender(PANEL + '/'))).ok, false, entry.login_url);
  }
});

test('the internal service shipped in sites.json needs host permission like the rest', async () => {
  const LAN = 'http://192.168.8.81:8085/login';
  const bg = backgroundHarness({granted: [originPattern(TARGET), 'http://192.168.8.81/*']});
  assert.equal((await bg.send(request(LAN), sender(PANEL + '/'))).ok, true);
  assert.equal(bg.tabs.get(bg.nextTabId()).url, LAN);

  const noPermission = backgroundHarness();
  const refused = await noPermission.send(request(LAN), sender(PANEL + '/'));
  assert.equal(refused.ok, false);
  assert.equal(refused.error, 'no_host_permission');
  assert.equal(noPermission.tabs.size, 0);
});

test('TARGET_CHECK confirms allowlisted pages only and never carries a password', async () => {
  const bg = backgroundHarness({localSites: [{
    name: 'CRM', login_url: CRM, username_selector: 'input#user', password_selector: 'input#pass'
  }]});
  const allowed = await bg.send({type: 'TARGET_CHECK'}, sender(CRM));
  assert.equal(allowed.ok, true);
  assert.equal(allowed.login_url, CRM);
  assert.equal(allowed.username_selector, 'input#user');
  assert.equal(allowed.password, undefined);
  assert.equal((await bg.send({type: 'TARGET_CHECK'}, sender(CRM + '?x=1'))).ok, false);
  assert.equal((await bg.send({type: 'TARGET_CHECK'}, sender('https://crm.example.com.evil.test/login'))).ok, false);
  assert.equal((await bg.send({type: 'TARGET_CHECK'}, sender(PANEL + '/'))).ok, false);
  assert.equal((await bg.send({type: 'LIST_SITES'}, sender(PANEL + '/'))).ok, false);
});

test('LIST_SITES reports the configured services and their permission state', async () => {
  const bg = backgroundHarness({
    localSites: [{name: 'CRM', login_url: CRM}],
    granted: [originPattern(TARGET)]
  });
  const result = await bg.send({type: 'LIST_SITES'}, popupSender);
  const shipped = JSON.parse(read('sites.json')).sites;
  assert.deepEqual(JSON.parse(JSON.stringify(result.sites)), [
    ...shipped.map(site => ({
      name: site.name,
      login_url: site.login_url,
      permitted: site.login_url === TARGET, // only the Activity host is pre-granted
      insecure: site.allow_insecure === true
    })),
    {name: 'CRM', login_url: CRM, permitted: false, insecure: false}
  ]);
});

function targetHarness({origin = new URL(TARGET).origin, method = 'POST', action = '',
                        submitAction = '', submitMethod = '', baseURI = '', passwordCount = 1,
                        confirmed = null, usernameSelector = '', passwordSelector = '',
                        submitSelector = ''} = {}) {
  const messages = [];
  const events = [];
  const window = {}; window.top = window;
  const location = {origin, pathname: '/login', href: origin + '/login'};
  class Input {
    constructor(type, name) {
      this.type = type; this.name = name; this.id = name; this.tagName = 'INPUT';
      this.disabled = false; this.readOnly = false; this.hidden = false;
      this.isConnected = true; this.autocomplete = '';
      this._value = '';
    }
    get value() {return this._value;}
    set value(value) {this._value = value;}
    dispatchEvent(event) {events.push(event.type);}
  }
  const username = new Input('text', 'username');
  const password = new Input('password', 'password');
  const submit = {disabled: false, tagName: 'BUTTON', getAttribute(attr) {
    return attr === 'formaction' ? submitAction : attr === 'formmethod' ? submitMethod : '';
  }};
  const form = {
    method, getAttribute(attr) {return attr === 'action' ? action : '';},
    querySelectorAll() {return [username, password];},
    // target.js asks for 'button[type="submit"], input[type="submit"]' or for
    // the configured submit selector.
    querySelector(selector) {
      return String(selector).includes('submit') || selector === 'button#go' ? submit : null;
    },
    requestSubmit() {form.submitted = true;}
  };
  username.form = form;
  password.form = form;
  const document = {
    baseURI: baseURI || location.href,
    querySelectorAll() {return passwordCount === 1 ? [password] : [password, new Input('password', 'repeat')];},
    querySelector(selector) {
      if (selector === 'input#user') return username;
      if (selector === 'input#pass') return password;
      return null;
    },
    documentElement: {}
  };
  const allowed = confirmed === null ? origin + '/login' === TARGET : confirmed;
  const chrome = {runtime: {async sendMessage(message) {
    messages.push(message);
    if (message.type === 'TARGET_CHECK') {
      return allowed
        ? {ok: true, login_url: TARGET, username_selector: usernameSelector,
           password_selector: passwordSelector, submit_selector: submitSelector}
        : {ok: false};
    }
    return {ok: true, username: fakeUser, password: fakePassword};
  }}};
  class MutationObserver {observe() {} disconnect() {}}
  class Event {constructor(type) {this.type = type;}}
  vm.runInNewContext(read('target.js'), {
    window, location, document, chrome, URL, HTMLInputElement: Input,
    MutationObserver, Event, setTimeout() {}
  });
  return {messages, events, form, username, password};
}

function bridgeHarness({unlocked = true, panelOrigin = PANEL, result = {ok: true}} = {}) {
  const listeners = {};
  const messages = [];
  const requests = [];
  const notifications = [];
  class Element {
    constructor() {this.dataset = {id: '3', autoLogin: '1'};}
    closest(selector) {return selector.startsWith('.mini-card') ? this : null;}
  }
  const card = new Element();
  const document = {
    body: {classList: {contains() {return false;}}, append() {}},
    createElement() {return {style: {}, setAttribute() {}, remove() {},
      set textContent(value) {notifications.push(value);}};},
    addEventListener(event, callback) {listeners[event] = callback;},
    querySelector() {return unlocked ? {content: 'vault-csrf-example'} : null;},
    getElementById() {return null;}
  };
  const location = {origin: PANEL, pathname: '/', assign(to) {location.navigated = to;}};
  const chrome = {
    storage: {local: {async get() {return {panelOrigin};}}},
    runtime: {async sendMessage(message) {messages.push(message); return result;}}
  };
  async function fetch(path, opts) {
    requests.push({path, opts});
    return {ok: true, status: 200, redirected: false,
      headers: {get() {return 'application/json';}},
      async json() {return {ok: true, login_url: TARGET, username: fakeUser, password: fakePassword};}}
  }
  vm.runInNewContext(read('bridge.js'), {
    chrome, document, location, Element, URL, URLSearchParams, fetch,
    setTimeout() {}
  });
  function click() {
    const event = {type: 'click', target: card, isTrusted: true, button: 0,
      preventDefault() {event.prevented = true;},
      stopImmediatePropagation() {event.stopped = true;}};
    listeners.click(event);
    return event;
  }
  return {listeners, messages, requests, notifications, location, click};
}

test('bridge fetches Vault only on a real card click, never posts passwords to the webpage', async () => {
  const b = bridgeHarness();
  await tick();
  const event = b.click();
  await tick();
  assert.equal(event.prevented, true);
  assert.equal(event.stopped, true);
  assert.equal(b.requests[0].path, '/vault/app/3/autologin');
  assert.equal(b.requests[0].opts.method, 'POST');
  assert.equal(b.requests[0].opts.credentials, 'same-origin');
  assert.equal(b.requests[0].opts.body, 'csrf_token=vault-csrf-example');
  assert.equal(b.messages[0].type, 'OPEN_LOGIN');
  assert.equal(b.messages[0].login_url, TARGET);
  assert.equal(b.messages[0].password, fakePassword);
  assert.equal(b.notifications.length, 0);
});

test('bridge asks for Vault unlock instead of releasing a password if locked', async () => {
  const b = bridgeHarness({unlocked: false});
  await tick();
  b.click();
  await tick();
  assert.equal(b.requests.length, 0);
  assert.equal(b.messages.length, 0);
  assert.equal(b.location.navigated, '/vault/login?next=%2F');
});

test('bridge explains a missing host permission without leaking the password', async () => {
  const b = bridgeHarness({result: {ok: false, error: 'no_host_permission'}});
  await tick();
  b.click();
  await tick();
  assert.equal(b.messages[0].type, 'OPEN_LOGIN');
  assert.equal(b.notifications.length, 1);
  assert.match(b.notifications[0], /не выдан доступ/i);
  assert.ok(!b.notifications[0].includes(fakePassword));
});

function popupHarness({tabUrl = PANEL + '/', proof = true,
                       sites = [{name: 'MSB Activity', login_url: TARGET, permitted: false}]} = {}) {
  const recorded = {permissions: [], removals: [], scripts: [], reloads: [], messages: []};
  const values = new Map();
  const granted = new Set();
  const button = {disabled: true, addEventListener(event, fn) {button.click = fn;}};
  const panel = {textContent: ''};
  const status = {textContent: '', className: ''};
  const list = {textContent: '', items: [], append(item) {this.items.push(item);}};
  const elements = {connect: button, panel, status, sites: list};
  const document = {
    getElementById(id) {return elements[id];},
    createElement() {return {textContent: ''};}
  };
  const chrome = {
    storage: {local: {
      async get(key) {return {[key]: values.get(key)};},
      async set(data) {for (const [key, val] of Object.entries(data)) values.set(key, val);}
    }},
    tabs: {
      async query() {return [{id: 33, url: tabUrl}];},
      async reload(id) {recorded.reloads.push(id);}
    },
    permissions: {
      async contains({origins}) {return origins.every(origin => granted.has(origin));},
      async request(opts) {
        recorded.permissions.push(opts);
        for (const origin of opts.origins) granted.add(origin);
        return true;
      },
      async remove(opts) {recorded.removals.push(opts); return true;}
    },
    scripting: {
      async executeScript() {return [{result: proof}];},
      async getRegisteredContentScripts() {return [];},
      async registerContentScripts(scripts) {recorded.scripts.push(...scripts);}
    },
    runtime: {
      async sendMessage(message) {
        recorded.messages.push(message);
        return message.type === 'LIST_SITES' ? {ok: true, sites} : {ok: true};
      }
    }
  };
  vm.runInNewContext(read('popup.js'), {document, chrome, URL});
  return {recorded, values, granted, button, panel, status, list};
}

test('popup registers a bridge only for the chosen HTTPS panel after verifying it', async () => {
  const popup = popupHarness();
  await tick();
  assert.equal(popup.button.disabled, false);
  assert.deepEqual(popup.list.items.map(item => item.textContent), [
    '⛔ MSB Activity — ' + TARGET
  ]);
  await popup.button.click();
  assert.equal(popup.values.get('panelOrigin'), PANEL);
  assert.deepEqual([...popup.recorded.permissions[0].origins], [PANEL + '/*', 'https://msb-activity.meryosab.com/*']);
  assert.equal(popup.recorded.scripts[0].matches[0], PANEL + '/*');
  assert.equal(popup.recorded.scripts[0].js[0], 'bridge.js');
  assert.deepEqual(popup.recorded.messages.map(message => message.type),
    ['LIST_SITES', 'REGISTER_TARGETS', 'LIST_SITES']);
  assert.deepEqual(popup.recorded.reloads, [33]);
});

test('popup asks for a private HTTP service but not for a public one', async () => {
  const popup = popupHarness({sites: [
    {name: 'LAN', login_url: 'http://192.168.8.81:8085/login', permitted: false, insecure: true},
    {name: 'Public', login_url: 'http://crm.example.com/login', permitted: false, insecure: false}
  ]});
  await tick();
  assert.deepEqual(popup.list.items.map(item => item.textContent), [
    '⛔ LAN — http://192.168.8.81:8085/login · http, пароль идёт открытым текстом',
    '⛔ Public — http://crm.example.com/login'
  ]);
  await popup.button.click();
  assert.deepEqual([...popup.recorded.permissions[0].origins],
    [PANEL + '/*', 'http://192.168.8.81/*']);
});

test('popup revokes newly granted hosts and disallows insecure remote panels', async () => {
  const fakeSite = popupHarness({proof: false});
  await tick();
  await fakeSite.button.click();
  assert.equal(fakeSite.recorded.scripts.length, 0);
  assert.deepEqual(fakeSite.recorded.removals.map(item => item.origins[0]),
    [PANEL + '/*', 'https://msb-activity.meryosab.com/*']);
  const insecure = popupHarness({tabUrl: 'http://192.168.1.4:5050/'});
  await tick();
  await insecure.button.click();
  assert.equal(insecure.recorded.permissions.length, 0);
  assert.equal(insecure.recorded.scripts.length, 0);
});

test('popup keeps host permissions that were granted before a failed reconnect', async () => {
  const popup = popupHarness({proof: false});
  await tick();
  popup.granted.add('https://msb-activity.meryosab.com/*');
  await popup.button.click();
  assert.deepEqual(popup.recorded.removals.map(item => item.origins[0]), [PANEL + '/*']);
});

test('target adapter fills one same-origin POST form and submits it', async () => {
  const t = targetHarness();
  await tick();
  assert.deepEqual(t.messages.map(message => message.type), ['TARGET_CHECK', 'TAKE_LOGIN']);
  assert.equal(t.username.value, fakeUser);
  assert.equal(t.password.value, fakePassword);
  assert.equal(t.form.submitted, true);
  assert.deepEqual(t.events, ['input', 'change', 'input', 'change']);
});

test('target adapter uses configured selectors when the form is unusual', async () => {
  const t = targetHarness({
    confirmed: true, passwordCount: 2,
    usernameSelector: 'input#user', passwordSelector: 'input#pass', submitSelector: 'button#go'
  });
  await tick();
  assert.equal(t.username.value, fakeUser);
  assert.equal(t.password.value, fakePassword);
  assert.equal(t.form.submitted, true);
});

test('target adapter stops when a configured selector does not resolve', async () => {
  const t = targetHarness({confirmed: true, passwordSelector: 'input#missing'});
  await tick();
  assert.deepEqual(t.messages.map(message => message.type), ['TARGET_CHECK']);
  assert.equal(t.form.submitted, undefined);
});

test('target adapter never requests secrets for a page the service worker did not confirm', async () => {
  for (const opts of [
    {origin: 'https://msb-activity.meryosab.com.evil.test'},
    {confirmed: false}
  ]) {
    const t = targetHarness(opts);
    await tick();
    assert.deepEqual(t.messages.map(message => message.type), ['TARGET_CHECK']);
    assert.equal(t.form.submitted, undefined);
  }
});

test('target adapter never fills GET, cross-origin or ambiguous forms', async () => {
  for (const opts of [
    {method: 'GET'}, {action: 'https://other.example.com/login'},
    {submitAction: 'https://other.example.com/steal'}, {submitMethod: 'GET'},
    {action: '/auth', baseURI: 'https://other.example.com/'},
    {passwordCount: 2}
  ]) {
    const t = targetHarness(opts);
    await tick();
    assert.deepEqual(t.messages.map(message => message.type), ['TARGET_CHECK']);
    assert.equal(t.form.submitted, undefined);
  }
});
