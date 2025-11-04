namespace Hello.Helpers;

public enum MessageSigningMode
{
    None,
    Installation,
    Account
}

public class AppSettings
{
    public byte[]? ApproovSecretBytes { get; set; }
    public MessageSigningMode MessageSigningMode { get; set; } = MessageSigningMode.None;
    public byte[]? AccountMessageBaseSecretBytes { get; set; }
    public string[] MessageSigningHeaderNames { get; set; } = Array.Empty<string>();
    public int MessageSigningMaxAgeSeconds { get; set; } = 300;
    public bool RequireSignatureNonce { get; set; }
}
