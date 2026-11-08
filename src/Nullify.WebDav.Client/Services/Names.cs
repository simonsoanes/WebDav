// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

namespace Nullify.WebDav.Client.Services;

public static class Names
{
    /// <summary>Mount, user and share names compare without regard to case, as on the server.</summary>
    public static bool Eq(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
}
