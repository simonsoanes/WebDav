// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0
// Applies a saved light/dark choice before first paint (an external file, so the CSP needs no inline scripts).
try {
    var t = localStorage.getItem('nullify.theme');
    if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
    if (localStorage.getItem('nullify.sidebarCollapsed') === '1') document.documentElement.dataset.sidebar = 'collapsed';
} catch (e) { }
