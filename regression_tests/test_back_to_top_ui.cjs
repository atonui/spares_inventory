const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const scriptPath = path.join(root, 'static/js/shared/back-to-top.js');

function loadController({ initialScrollY = 0, reducedMotion = false } = {}) {
  const frames = [];
  const listeners = {};
  const buttonListeners = {};
  const button = {
    hidden: false,
    addEventListener(type, listener) {
      buttonListeners[type] = listener;
    },
  };
  const window = {
    requestAnimationFrame(callback) { frames.push(callback); },
    scrollY: initialScrollY,
    addEventListener(type, listener) {
      listeners[type] = listener;
    },
    matchMedia() {
      return { matches: reducedMotion };
    },
    scrollTo(options) {
      this.lastScrollTo = options;
    },
  };
  const document = {
    getElementById(id) {
      return id === 'back-to-top' ? button : null;
    },
  };
  vm.runInNewContext(fs.readFileSync(scriptPath, 'utf8'), { window, document });
  function flushFrame() { const callbacks = frames.splice(0); callbacks.forEach(callback => callback()); }
  flushFrame();
  return { button, buttonListeners, listeners, window, frames, flushFrame };
}

test('long-scroll pages include an accessible Back to top button', () => {
  for (const page of ['index.html', 'superadmin.html']) {
    const html = fs.readFileSync(path.join(root, 'static', page), 'utf8');
    assert.match(html, /id="back-to-top"/);
    assert.match(html, /aria-label="Back to top"/);
    assert.match(html, /js\/shared\/back-to-top\.js/);
    assert.match(html, /back-to-top\.css/);
  }
  const css = fs.readFileSync(path.join(root, 'static/back-to-top.css'), 'utf8');
  assert.match(css, /:focus-visible/);
  assert.match(css, /min-height:\s*44px/);
});

test('short account and authentication pages do not include the floating control', () => {
  for (const page of ['profile.html', 'accept_invitation.html', 'forgot_password.html', 'reset_password.html']) {
    const html = fs.readFileSync(path.join(root, 'static', page), 'utf8');
    assert.doesNotMatch(html, /id="back-to-top"/);
    assert.doesNotMatch(html, /js\/shared\/back-to-top\.js/);
  }
});

test('button stays hidden near the top and appears after the scroll threshold', () => {
  const { button, listeners, window, flushFrame } = loadController();
  assert.equal(button.hidden, true);
  window.scrollY = 500;
  listeners.scroll();
  flushFrame();
  assert.equal(button.hidden, false);
  window.scrollY = 120;
  listeners.scroll();
  flushFrame();
  assert.equal(button.hidden, true);
});

test('button scrolls smoothly unless reduced motion is requested', () => {
  const normal = loadController({ initialScrollY: 800 });
  normal.buttonListeners.click();
  assert.equal(normal.window.lastScrollTo.top, 0);
  assert.equal(normal.window.lastScrollTo.behavior, 'smooth');

  const reduced = loadController({ initialScrollY: 800, reducedMotion: true });
  reduced.buttonListeners.click();
  assert.equal(reduced.window.lastScrollTo.top, 0);
  assert.equal(reduced.window.lastScrollTo.behavior, 'auto');
});

test('scroll and resize bursts share one frame and avoid repeated DOM writes', () => {
  const {button, listeners, window, frames, flushFrame} = loadController();
  let writes = 0;
  let hidden = button.hidden;
  Object.defineProperty(button, 'hidden', {get:()=>hidden, set:value=>{writes++;hidden=value;}});
  window.scrollY = 600;
  for (let i=0;i<20;i++) { listeners.scroll(); listeners.resize(); }
  assert.equal(frames.length,1);
  assert.equal(writes,0);
  flushFrame();
  assert.equal(writes,1);
  window.scrollY = 900;
  listeners.scroll(); flushFrame();
  assert.equal(writes,1);
  window.scrollY = 0;
  listeners.scroll(); flushFrame();
  assert.equal(writes,2);
  assert.equal(button.hidden,true);
});
