const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const staticRoot = path.resolve(__dirname, '../../static');
const pages = new Set(['index.html', 'profile.html', 'forgot_password.html', 'reset_password.html', 'superadmin.html']);
const loaded = new WeakMap();

function pageScripts(page) {
    if (!pages.has(page)) throw new Error('Unknown frontend page: ' + page);
    const html = fs.readFileSync(path.join(staticRoot, page), 'utf8').replace(/<!--[\s\S]*?-->/g, '');
    const result = [];
    const seen = new Set();
    for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
        const attrs = match[1];
        const srcMatch = attrs.match(/\bsrc\s*=\s*(["'])(.*?)\1/i);
        if (!srcMatch) {
            if (match[2].trim()) throw new Error('Executable inline script in ' + page);
            continue;
        }
        const src = srcMatch[2];
        const defer = /(?:^|\s)defer(?:\s|$)/i.test(attrs);
        let localPath = null;
        if (!/^(?:https?:)?\/\//i.test(src)) {
            const relative = decodeURIComponent(src.split(/[?#]/)[0]);
            localPath = path.resolve(staticRoot, relative);
            if (!localPath.startsWith(staticRoot + path.sep)) throw new Error('Script escapes static directory: ' + src);
            if (/(?:^|\s)async(?:\s|$)/i.test(attrs)) throw new Error('Async local script: ' + src);
            if (!defer) throw new Error('Local script must defer: ' + src);
            if (seen.has(localPath)) throw new Error('Duplicate local script: ' + src);
            seen.add(localPath);
            if (!fs.statSync(localPath).isFile()) throw new Error('Missing local script: ' + src);
        }
        result.push({src, localPath, defer});
    }
    return result;
}

function loadPageScripts(page, context) {
    if (!vm.isContext(context)) throw new Error('Expected a VM context');
    // Validate the full page before skipping shared files in combined fixtures.
    const scripts = pageScripts(page);
    if (!loaded.has(context)) loaded.set(context, new Set());
    const executed = loaded.get(context);
    for (const script of scripts) {
        if (!script.localPath || executed.has(script.localPath)) continue;
        vm.runInContext(fs.readFileSync(script.localPath, 'utf8'), context, {filename: script.localPath});
        executed.add(script.localPath);
    }
    return context;
}

module.exports = {pageScripts, loadPageScripts};
