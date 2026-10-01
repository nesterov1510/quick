import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import vm from 'node:vm';

const read = name => readFileSync(new URL(`../${name}`, import.meta.url), 'utf8');
const TARGET = 'https://msb-activity.meryosab.com/login';
const PANEL = 'https://quick.example.com';
const fakeUser = 'test-user';
const fakePassword = 'not-a-real-password';

function backgroundHarness() {
  const local = new Map([['panelOrigin', PANEL]]);
  const session = new Map();
  const alarms = new Map();
  const tabs = new Map();
  const handlers = {};
  let tabId = 100;
  const area = map => ({
    async get(key) {return {[key]: map.get(key)};},
    async set(values) {for (const [key, value] of Object.entries(values)) map.set(key, value);},
    async remove(key) {map.delete(key);}
  });
  const chrome = {
    runtime: {id: 'quick-extension', onMessage: {addListener(fn) {handlers.message = fn;}}},
    storage: {local: area(local), session: area(session)},
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
  vm.runInNewContext(read('background.js'), {chrome, URL, Date});
  function send(message, sender) {
    return new Promise(resolve => {
      if (handlers.message(message, sender, resolve) !== true) resolve(undefined);
    });
  }
  return {local, session, alarms, tabs, handlers, send, nextTabId: () => tabId};
}

const sender = (url, id = 1) => ({id: 'quick-extension', frameId: 0, tab: {id}, url});
const request = () => ({type: 'OPEN_LOGIN', login_url: TARGET, username: fakeUser, password: fakePassword});

test('background accepts only the configured panel and the pinned HTTPS target', async () => {
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

function targetHarness({origin = new URL(TARGET).origin, method = 'POST', action = '',
                        submitAction = '', submitMethod = '', baseURI = '', passwordCount = 1} = {}) {
  const messages = [];
  const events = [];
  const window = {}; window.top = window;
  const location = {origin, pathname: '/login', href: origin + '/login'};
  class Input {
    constructor(type, name) {
      this.type = type; this.name = name; this.id = name;
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
  const submit = {disabled: false, getAttribute(attr) {
    return attr === 'formaction' ? submitAction : attr === 'formmethod' ? submitMethod : '';
  }};
  const form = {
    method, getAttribute(attr) {return attr === 'action' ? action : '';},
    querySelectorAll() {return [username, password];},
    querySelector() {return submit;},
    requestSubmit() {form.submitted = true;}
  };
  password.form = form;
  const document = {
    baseURI: baseURI || location.href,
    querySelectorAll() {return passwordCount === 1 ? [password] : [password, new Input('password', 'repeat')];},
    documentElement: {}
  };
  const chrome = {runtime: {async sendMessage(message) {
    messages.push(message);
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

function bridgeHarness({unlocked = true, panelOrigin = PANEL} = {}) {
  const listeners = {};
  const messages = [];
  const requests = [];
  class Element {
    constructor() {this.dataset = {id: '3', autoLogin: '1'};}
    closest(selector) {return selector.startsWith('.mini-card') ? this : null;}
  }
  const card = new Element();
  const document = {
    body: {classList: {contains() {return false;}}, append() {}},
    createElement() {return {style: {}, setAttribute() {}, remove() {}};},
    addEventListener(event, callback) {listeners[event] = callback;},
    querySelector() {return unlocked ? {content: 'vault-csrf-example'} : null;},
    getElementById() {return null;}
  };
  const location = {origin: PANEL, pathname: '/', assign(to) {location.navigated = to;}};
  const chrome = {
    storage: {local: {async get() {return {panelOrigin};}}},
    runtime: {async sendMessage(message) {messages.push(message); return {ok: true};}}
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
  return {listeners, messages, requests, location, click};
}

test('bridge fetches Vault only on a real card click, never posts passwords to the webpage', async () => {
  const b = bridgeHarness();
  await new Promise(resolve => setImmediate(resolve));
  const event = b.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(event.prevented, true);
  assert.equal(event.stopped, true);
  assert.equal(b.requests[0].path, '/vault/app/3/autologin');
  assert.equal(b.requests[0].opts.method, 'POST');
  assert.equal(b.requests[0].opts.credentials, 'same-origin');
  assert.equal(b.requests[0].opts.body, 'csrf_token=vault-csrf-example');
  assert.equal(b.messages[0].type, 'OPEN_LOGIN');
  assert.equal(b.messages[0].login_url, TARGET);
  assert.equal(b.messages[0].password, fakePassword);
});

test('bridge asks for Vault unlock instead of releasing a password if locked', async () => {
  const b = bridgeHarness({unlocked: false});
  await new Promise(resolve => setImmediate(resolve));
  b.click();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(b.requests.length, 0);
  assert.equal(b.messages.length, 0);
  assert.equal(b.location.navigated, '/vault/login?next=%2F');
});

function popupHarness({tabUrl = PANEL + '/', proof = true} = {}) {
  const recorded = {permissions: [], removals: [], scripts: [], reloads: []};
  const values = new Map();
  const button = {disabled: true, addEventListener(event, fn) {button.click = fn;}};
  const panel = {textContent: ''};
  const status = {textContent: '', className: ''};
  const elements = {connect: button, panel, status};
  const document = {getElementById(id) {return elements[id];}};
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
      async request(opts) {recorded.permissions.push(opts); return true;},
      async remove(opts) {recorded.removals.push(opts); return true;}
    },
    scripting: {
      async executeScript() {return [{result: proof}];},
      async getRegisteredContentScripts() {return [];},
      async registerContentScripts(scripts) {recorded.scripts.push(...scripts);}
    }
  };
  vm.runInNewContext(read('popup.js'), {document, chrome, URL});
  return {recorded, values, button, panel, status};
}

test('popup registers a bridge only for the chosen HTTPS panel after verifying it', async () => {
  const popup = popupHarness();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(popup.button.disabled, false);
  await popup.button.click();
  assert.equal(popup.values.get('panelOrigin'), PANEL);
  assert.equal(popup.recorded.permissions[0].origins[0], PANEL + '/*');
  assert.equal(popup.recorded.scripts[0].matches[0], PANEL + '/*');
  assert.equal(popup.recorded.scripts[0].js[0], 'bridge.js');
  assert.deepEqual(popup.recorded.reloads, [33]);
});

test('popup revokes a rejected site and disallows insecure remote panels', async () => {
  const fakeSite = popupHarness({proof: false});
  await new Promise(resolve => setImmediate(resolve));
  await fakeSite.button.click();
  assert.equal(fakeSite.recorded.scripts.length, 0);
  assert.equal(fakeSite.recorded.removals.length, 1);
  const insecure = popupHarness({tabUrl: 'http://192.168.1.4:5050/'});
  await new Promise(resolve => setImmediate(resolve));
  await insecure.button.click();
  assert.equal(insecure.recorded.permissions.length, 0);
  assert.equal(insecure.recorded.scripts.length, 0);
});

test('target adapter fills one same-origin POST form and submits it', async () => {
  const t = targetHarness();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(t.messages.length, 1);
  assert.equal(t.messages[0].type, 'TAKE_LOGIN');
  assert.equal(t.username.value, fakeUser);
  assert.equal(t.password.value, fakePassword);
  assert.equal(t.form.submitted, true);
  assert.deepEqual(t.events, ['input', 'change', 'input', 'change']);
});

test('target adapter never requests secrets for wrong origin, GET, cross-origin action or ambiguous forms', () => {
  for (const opts of [
    {origin: 'https://msb-activity.meryosab.com.evil.test'},
    {method: 'GET'}, {action: 'https://other.example.com/login'},
    {submitAction: 'https://other.example.com/steal'}, {submitMethod: 'GET'},
    {action: '/auth', baseURI: 'https://other.example.com/'},
    {passwordCount: 2}
  ]) {
    const t = targetHarness(opts);
    assert.equal(t.messages.length, 0);
    assert.equal(t.form.submitted, undefined);
  }
});
