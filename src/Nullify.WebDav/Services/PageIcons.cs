// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebDav.Services;

/// <summary>The few stroke icons the server-rendered pages use; the same drawings as the file manager's Icon component.</summary>
public static class PageIcons
{
    private static readonly Dictionary<string, string> Paths = new()
    {
        ["folder"] = """<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5h3.6l2 2.5h7.4A2.5 2.5 0 0 1 21 10v7.5a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z"/>""",
        ["plug"] = """<path d="M9 3v4.5M15 3v4.5"/><path d="M6.5 7.5h11V11a5.5 5.5 0 0 1-11 0z"/><path d="M12 16.5V21"/>""",
        ["key"] = """<circle cx="8" cy="15.5" r="4.5"/><path d="M11.2 12.3 20 3.5M17 6.5l2.5 2.5M14.5 9l2 2"/>""",
        ["users"] = """<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M15.5 4.8a3.5 3.5 0 0 1 0 6.4M17.5 14.2a6.5 6.5 0 0 1 4 5.8"/>""",
        ["hard-drive"] = """<path d="M3 13 5.6 6.4A2 2 0 0 1 7.5 5h9a2 2 0 0 1 1.9 1.4L21 13"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h5M16.5 16.5h.01"/>""",
        ["share"] = """<circle cx="18" cy="5.5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="18.5" r="2.5"/><path d="m8.2 10.8 7.6-4.1M8.2 13.2l7.6 4.1"/>""",
        ["shield"] = """<path d="M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6z"/>""",
        ["settings"] = """<path d="M10.14 5.05L10.5 2.52L13.5 2.52L13.86 5.05L15.6 5.76L17.64 4.23L19.77 6.36L18.24 8.4L18.95 10.14L21.48 10.5L21.48 13.5L18.95 13.86L18.24 15.6L19.77 17.64L17.64 19.77L15.6 18.24L13.86 18.95L13.5 21.48L10.5 21.48L10.14 18.95L8.4 18.24L6.36 19.77L4.23 17.64L5.76 15.6L5.05 13.86L2.52 13.5L2.52 10.5L5.05 10.14L5.76 8.4L4.23 6.36L6.36 4.23L8.4 5.76z"/><circle cx="12" cy="12" r="3"/>""",
        ["logout"] = """<path d="M10 4H6.5A2.5 2.5 0 0 0 4 6.5v11A2.5 2.5 0 0 0 6.5 20H10"/><path d="M10 12h10.5M16.5 8l4 4-4 4"/>""",
        ["menu"] = """<path d="M4 6.5h16M4 12h16M4 17.5h16"/>""",
        ["user"] = """<circle cx="12" cy="8" r="4"/><path d="M4.5 21a7.5 7.5 0 0 1 15 0"/>""",
        ["lock"] = """<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5M12 14.5v2"/>""",
        ["copy"] = """<rect x="8.5" y="8.5" width="12" height="12" rx="2.5"/><path d="M15.5 8.5V6a2.5 2.5 0 0 0-2.5-2.5H6A2.5 2.5 0 0 0 3.5 6v7A2.5 2.5 0 0 0 6 15.5h2.5"/>""",
        ["download"] = """<path d="M4 15.5V18a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2.5"/><path d="M12 4v11M7.5 10.5 12 15l4.5-4.5"/>""",
    };

    public static string Get(string name, int size = 18) =>
        $"""<svg class="icon" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">{Paths.GetValueOrDefault(name, "")}</svg>""";
}
