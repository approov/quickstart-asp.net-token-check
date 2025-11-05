namespace Hello.Helpers;

// Holds runtime configuration injected into the request-processing pipeline.
public class AppSettings
{
    public byte[]? ApproovSecretBytes { get; set; }
    public string? TokenBindingHeader { get; set; }
}
