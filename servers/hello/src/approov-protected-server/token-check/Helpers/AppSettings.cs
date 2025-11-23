namespace Hello.Helpers;

using System;
using System.Collections.Generic;

// Holds runtime configuration injected into the request-processing pipeline.
public class AppSettings
{
    public byte[]? ApproovSecretBytes { get; set; }

    // Comma-delimited header list used when recomputing the Approov token binding hash.
    public IList<string> TokenBindingHeaders { get; set; } = new List<string>();
}

// Tweaks applied to HTTP message signature validation without needing code changes.
public sealed class MessageSignatureValidationOptions
{
    // When true we require a `created` parameter and optionally enforce an age window.
    public bool RequireCreated { get; set; } = true;

    // When true we require an `expires` parameter and ensure it has not elapsed.
    public bool RequireExpires { get; set; } = false;

    // Optional freshness window applied to the `created` timestamp.
    public TimeSpan? MaximumSignatureAge { get; set; } = null;

    // Permits small client/server drift when checking created/expires timestamps.
    public TimeSpan AllowedClockSkew { get; set; } = TimeSpan.Zero;
}
