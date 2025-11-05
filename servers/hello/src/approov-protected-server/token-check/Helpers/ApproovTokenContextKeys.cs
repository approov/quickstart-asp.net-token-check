namespace Hello.Helpers;

// Centralises the HttpContext.Items keys used by the Approov middleware chain.
public static class ApproovTokenContextKeys
{
    public const string ApproovToken = "ApproovToken";
    public const string DeviceId = "ApproovDeviceId";
    public const string TokenExpiry = "ApproovTokenExpiry";
    public const string InstallationPublicKey = "ApproovInstallationPublicKey";
    public const string TokenBinding = "ApproovTokenBinding";
    public const string TokenBindingVerified = "ApproovTokenBindingVerified";
}
