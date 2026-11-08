// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
//
// Browser-side helpers for the Nullify.WebDav file manager: drag and drop, uploads with progress (XMLHttpRequest,
// straight from the File objects, so large files never pass through WebAssembly memory) and menu placement.
// No dependencies.
(() => {
    'use strict';

    let dotnet = null;
    let nextBatch = 1;
    const batches = new Map();
    let internalDrag = false;

    const encodePath = (path) => path.split('/').map(encodeURIComponent).join('/');
    const hasFiles = (e) => !!e.dataTransfer && [...e.dataTransfer.types].includes('Files');
    const targetOf = (e) => e.target instanceof Element ? e.target.closest('[data-drop-url]') : null;
    const shell = () => document.querySelector('.docs-shell');

    let marked = null;
    const mark = (el) => {
        if (marked === el) return;
        if (marked) marked.classList.remove('drop-target');
        marked = el;
        if (el) el.classList.add('drop-target');
    };
    let overlayDepth = 0;
    const clearDrop = () => {
        mark(null);
        overlayDepth = 0;
        const s = shell();
        if (s) delete s.dataset.drop;
    };

    // ------------------------------------------------------------------ collecting dropped or picked files

    function readEntries(reader) {
        return new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    }

    async function walk(entry, prefix, out) {
        if (entry.isFile) {
            const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
            out.files.push({ file, path: prefix + entry.name });
        } else if (entry.isDirectory) {
            const dir = prefix + entry.name;
            out.dirs.push(dir);
            const reader = entry.createReader();
            for (; ;) {
                const batch = await readEntries(reader);
                if (batch.length === 0) break;
                for (const child of batch) await walk(child, dir + '/', out);
            }
        }
    }

    async function register(target, collected) {
        if (collected.files.length === 0 && collected.dirs.length === 0) return;
        const id = nextBatch++;
        batches.set(id, { target, ...collected, xhr: null, cancelled: false });
        const tops = new Map();
        for (const d of collected.dirs) { const t = d.split('/')[0]; tops.set(t, true); }
        for (const f of collected.files) { const t = f.path.split('/')[0]; if (!tops.has(t)) tops.set(t, f.path.includes('/')); }
        const total = collected.files.reduce((n, f) => n + f.file.size, 0);
        await dotnet.invokeMethodAsync('UploadChosen', id, target,
            [...tops.keys()], [...tops.values()], collected.files.length, total);
    }

    // ------------------------------------------------------------------ drag and drop

    function onDragStart(e) {
        const row = e.target instanceof Element ? e.target.closest('[data-drag-url]') : null;
        if (!row || !dotnet) return;
        internalDrag = true;
        e.dataTransfer.effectAllowed = 'copyMove';
        // Firefox only starts a drag that carries data.
        e.dataTransfer.setData('text/plain', row.dataset.dragName || '');
        dotnet.invokeMethodAsync('DragStarted', row.dataset.dragUrl);
    }

    function onDragOver(e) {
        const files = hasFiles(e);
        if (!files && !internalDrag) return;
        e.preventDefault(); // never let the browser open dropped files in place of the app
        const target = targetOf(e);
        const url = target ? target.dataset.dropUrl : null;
        if (!url || (internalDrag && target.dataset.dragUrl && target.classList.contains('selected'))) {
            e.dataTransfer.dropEffect = 'none';
            mark(null);
            return;
        }
        e.dataTransfer.dropEffect = files ? 'copy' : (e.ctrlKey || e.metaKey || e.altKey ? 'copy' : 'move');
        // The whole pane stands for the current folder; rows, crumbs and sidebar entries are highlighted themselves.
        mark(target.classList.contains('docs-shell') ? null : target);
    }

    function onDragEnter(e) {
        if (!hasFiles(e)) return;
        const s = shell();
        if (s && s.dataset.dropUrl && s.contains(e.target)) { overlayDepth++; s.dataset.drop = ''; }
    }

    function onDragLeave(e) {
        if (!hasFiles(e)) { if (e.target === marked) mark(null); return; }
        const s = shell();
        if (s && s.contains(e.target) && overlayDepth > 0 && --overlayDepth === 0) delete s.dataset.drop;
    }

    async function onDrop(e) {
        const files = hasFiles(e);
        if (!files && !internalDrag) return;
        e.preventDefault();
        const target = targetOf(e);
        const url = target ? target.dataset.dropUrl : null;
        const copy = e.ctrlKey || e.metaKey || e.altKey;
        clearDrop();
        if (!url) { internalDrag = false; return; }

        if (!files) {
            internalDrag = false;
            if (target.dataset.dragUrl && target.classList.contains('selected')) return;
            await dotnet.invokeMethodAsync('DropItems', url, copy);
            return;
        }

        // Entries must be taken synchronously, before the first await.
        const entries = [...e.dataTransfer.items].filter(i => i.kind === 'file')
            .map(i => (i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
        const plain = [...e.dataTransfer.files];
        const collected = { files: [], dirs: [] };
        try {
            if (entries.length > 0 && entries.every(x => x)) {
                for (const entry of entries) await walk(entry, '', collected);
            } else {
                for (const file of plain) collected.files.push({ file, path: file.name });
            }
        } catch (err) {
            dotnet.invokeMethodAsync('UploadFailedToRead', String(err && err.message || err));
            return;
        }
        await register(url, collected);
    }

    // ------------------------------------------------------------------ uploading

    function put(batch, item, overwrite, onProgress) {
        return new Promise((resolve) => {
            const xhr = new XMLHttpRequest();
            batch.xhr = xhr;
            xhr.open('PUT', batch.target + encodePath(item.path));
            xhr.setRequestHeader('X-Nullify-Request', '1');
            if (!overwrite) xhr.setRequestHeader('If-None-Match', '*');
            if (item.file.lastModified) xhr.setRequestHeader('X-OC-Mtime', String(Math.floor(item.file.lastModified / 1000)));
            xhr.setRequestHeader('Content-Type', item.file.type || 'application/octet-stream');
            xhr.upload.onprogress = (ev) => onProgress(ev.loaded);
            xhr.onload = () => resolve({ status: xhr.status, text: (xhr.getResponseHeader('Content-Type') || '').startsWith('text/plain') ? xhr.responseText : '' });
            xhr.onerror = () => resolve({ status: 0, text: 'The connection failed.' });
            xhr.onabort = () => resolve({ status: -1, text: 'Cancelled' });
            xhr.send(item.file);
        });
    }

    async function mkcol(url) {
        const r = await fetch(url, { method: 'MKCOL', headers: { 'X-Nullify-Request': '1' }, credentials: 'same-origin' });
        return r.ok || r.status === 405 ? 0 : r.status;
    }

    async function upload(id, overwrite) {
        const batch = batches.get(id);
        if (!batch) return;
        const total = batch.files.reduce((n, f) => n + f.file.size, 0);
        const failures = [];
        let done = 0, ok = 0, last = 0;
        const report = (index, name, sent, force) => {
            const now = performance.now();
            if (!force && now - last < 120) return;
            last = now;
            dotnet.invokeMethodAsync('UploadProgress', id, index, batch.files.length, name, sent, total);
        };

        for (const dir of [...batch.dirs].sort((a, b) => a.split('/').length - b.split('/').length)) {
            if (batch.cancelled) break;
            const status = await mkcol(batch.target + encodePath(dir) + '/');
            if (status) failures.push({ name: dir, status, message: '' });
        }
        for (let i = 0; i < batch.files.length && !batch.cancelled; i++) {
            const item = batch.files[i];
            report(i + 1, item.path, done, true);
            const result = await put(batch, item, overwrite, (loaded) => report(i + 1, item.path, done + loaded, false));
            if (result.status === -1) break;
            if (result.status >= 200 && result.status < 300) ok++;
            else failures.push({ name: item.path, status: result.status, message: result.text.slice(0, 300) });
            done += item.file.size;
        }
        report(batch.files.length, '', done, true);
        batches.delete(id);
        await dotnet.invokeMethodAsync('UploadDone', id, ok, failures.map(f => f.name), failures.map(f => f.status),
            failures.map(f => f.message), batch.cancelled);
    }

    // ------------------------------------------------------------------ public API

    window.nullifyFiles = {
        init(ref) {
            dotnet = ref;
            if (window._nullifyFilesInit) return;
            window._nullifyFilesInit = true;
            document.addEventListener('dragstart', onDragStart);
            document.addEventListener('dragend', () => { internalDrag = false; clearDrop(); });
            document.addEventListener('dragenter', onDragEnter);
            document.addEventListener('dragleave', onDragLeave);
            document.addEventListener('dragover', onDragOver);
            document.addEventListener('drop', onDrop);
        },

        /** Opens the file (or folder) picker; the choice is registered like a drop onto the target folder. */
        pick(target, folders) {
            const input = document.createElement('input');
            input.type = 'file';
            input.multiple = true;
            if (folders) input.webkitdirectory = true;
            input.style.display = 'none';
            input.addEventListener('change', () => {
                const collected = { files: [], dirs: [] };
                const dirs = new Set();
                for (const file of input.files) {
                    const path = folders && file.webkitRelativePath ? file.webkitRelativePath : file.name;
                    collected.files.push({ file, path });
                    const parts = path.split('/');
                    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
                }
                collected.dirs = [...dirs];
                input.remove();
                register(target, collected);
            });
            document.body.appendChild(input);
            input.click();
        },

        startUpload(id, overwrite) { upload(id, overwrite); },
        discardUpload(id) { batches.delete(id); },
        cancelUpload(id) {
            const batch = batches.get(id);
            if (!batch) return;
            batch.cancelled = true;
            if (batch.xhr) batch.xhr.abort();
        },

        confirm(message) { return window.confirm(message); },

        async copyText(text) {
            try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
        },

        /** Downloads several files one after the other (browsers ask once to allow multiple downloads). */
        downloadAll(urls) {
            urls.forEach((url, i) => setTimeout(() => {
                const a = document.createElement('a');
                a.href = url;
                a.download = '';
                document.body.appendChild(a);
                a.click();
                a.remove();
            }, i * 400));
        },

        /** Focuses a name field with the part before the extension selected, as file managers do. */
        focusName(el, selectStem) {
            if (!el) return;
            el.focus();
            const dot = el.value.lastIndexOf('.');
            el.setSelectionRange(0, selectStem && dot > 0 ? dot : el.value.length);
        },

        focus(el) { if (el) el.focus({ preventScroll: true }); },

        scrollIntoView(selector) {
            const el = document.querySelector(selector);
            if (el) el.scrollIntoView({ block: 'nearest' });
        },

        /** Keep a context menu opened at (x, y) inside the window; focus its first item when it opens. */
        fitMenu(el, x, y, first) {
            if (!el) return;
            const pad = 8;
            const w = el.offsetWidth, h = el.offsetHeight;
            el.style.left = Math.max(pad, Math.min(x, window.innerWidth - w - pad)) + 'px';
            el.style.top = Math.max(pad, Math.min(y, window.innerHeight - h - pad)) + 'px';
            if (first) {
                const item = el.querySelector('.menu-item:not(:disabled)');
                if (item) item.focus({ preventScroll: true });
            }
        },

        menuStep(el, step) {
            const items = [...el.querySelectorAll('.menu-item:not(:disabled)')];
            if (items.length === 0) return;
            const i = items.indexOf(document.activeElement);
            items[(i + step + items.length) % items.length].focus();
        },

        toggleRail() {
            const root = document.documentElement;
            const collapsed = root.dataset.sidebar === 'collapsed';
            if (collapsed) delete root.dataset.sidebar; else root.dataset.sidebar = 'collapsed';
            try { localStorage.setItem('nullify.sidebarCollapsed', collapsed ? '0' : '1'); } catch { }
        },

        toggleTheme() {
            const root = document.documentElement;
            const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
            root.dataset.theme = dark ? 'light' : 'dark';
            try { localStorage.setItem('nullify.theme', root.dataset.theme); } catch { }
        },
    };
})();
