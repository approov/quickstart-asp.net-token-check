using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Configuration;
using Hello.Helpers;

//////////////////////////
// SETUP APPROOV SECRET
//////////////////////////

DotNetEnv.Env.Load();

var approovBase64Secret = DotNetEnv.Env.GetString("APPROOV_BASE64_SECRET");

if(approovBase64Secret == null) {
    throw new Exception("Missing the env var APPROOV_BASE64_SECRET or its empty.");
}

var approovSecretBytes = System.Convert.FromBase64String(approovBase64Secret);


///////////////
// BUILD APP
///////////////

// Add services to the container.

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var approovSection = builder.Configuration.GetSection("Approov");
var messageSigningModeValue = approovSection["MessageSigningMode"] ?? nameof(MessageSigningMode.None);
if (!Enum.TryParse<MessageSigningMode>(messageSigningModeValue, true, out var messageSigningMode))
{
    throw new InvalidOperationException($"Unsupported Approov message signing mode '{messageSigningModeValue}'.");
}

var accountMessageBaseSecretRaw = approovSection["AccountMessageBaseSecret"];
byte[]? accountMessageBaseSecretBytes = null;
if (!string.IsNullOrWhiteSpace(accountMessageBaseSecretRaw))
{
    accountMessageBaseSecretBytes = DecodeAccountMessageBaseSecret(accountMessageBaseSecretRaw);
}

if (messageSigningMode == MessageSigningMode.Account && accountMessageBaseSecretBytes == null)
{
    throw new InvalidOperationException("Message signing mode 'Account' requires Approov:AccountMessageBaseSecret to be configured.");
}

var configuredSignedHeaders = approovSection.GetSection("SignedHeaders").Get<string[]>() ?? Array.Empty<string>();
var messageSigningHeaderNames = NormalizeSignedHeaders(configuredSignedHeaders);
var messageSigningMaxAgeSeconds = approovSection.GetValue<int?>("MessageSigningMaxAgeSeconds") ?? 300;
if (messageSigningMaxAgeSeconds < 0)
{
    throw new InvalidOperationException("Approov:MessageSigningMaxAgeSeconds cannot be negative.");
}
var requireSignatureNonce = approovSection.GetValue<bool?>("RequireSignatureNonce") ?? false;

builder.Services.Configure<AppSettings>(appSettings =>
{
    appSettings.ApproovSecretBytes = approovSecretBytes;
    appSettings.MessageSigningMode = messageSigningMode;
    appSettings.AccountMessageBaseSecretBytes = accountMessageBaseSecretBytes;
    appSettings.MessageSigningHeaderNames = messageSigningHeaderNames;
    appSettings.MessageSigningMaxAgeSeconds = messageSigningMaxAgeSeconds;
    appSettings.RequireSignatureNonce = requireSignatureNonce;
});

var app = builder.Build();


//////////////
// RUN APP
//////////////

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// app.UseHttpsRedirection();

app.UseMiddleware<Hello.Middleware.ApproovTokenMiddleware>();
app.UseMiddleware<Hello.Middleware.MessageSigningMiddleware>();

app.UseAuthorization();

app.MapControllers();

app.Run();

static byte[] DecodeAccountMessageBaseSecret(string encodedSecret)
{
    var sanitized = encodedSecret.Trim();
    if (string.IsNullOrWhiteSpace(sanitized))
    {
        throw new FormatException("Account message signing base secret cannot be empty.");
    }

    try
    {
        return Convert.FromBase64String(sanitized);
    }
    catch (FormatException)
    {
        // Intentionally fall through to try Base32 decoding.
    }

    return DecodeBase32(sanitized);
}

static byte[] DecodeBase32(string encodedSecret)
{
    const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var cleaned = encodedSecret
        .Trim()
        .Replace("-", string.Empty)
        .Replace(" ", string.Empty)
        .TrimEnd('=')
        .ToUpperInvariant();

    if (cleaned.Length == 0)
    {
        throw new FormatException("Account message signing base secret cannot be empty.");
    }

    var output = new List<byte>();
    var buffer = 0;
    var bitsLeft = 0;

    foreach (var ch in cleaned)
    {
        var index = alphabet.IndexOf(ch);
        if (index < 0)
        {
            throw new FormatException($"Invalid Base32 character '{ch}'.");
        }

        buffer = (buffer << 5) | index;
        bitsLeft += 5;

        if (bitsLeft >= 8)
        {
            bitsLeft -= 8;
            var value = (byte)((buffer >> bitsLeft) & 0xFF);
            output.Add(value);
            buffer &= (1 << bitsLeft) - 1;
        }
    }

    if (bitsLeft > 0 && (buffer & ((1 << bitsLeft) - 1)) != 0)
    {
        throw new FormatException("Invalid Base32 padding in account message signing base secret.");
    }

    if (output.Count == 0)
    {
        throw new FormatException("Account message signing base secret decoding produced no data.");
    }

    return output.ToArray();
}

static string[] NormalizeSignedHeaders(IEnumerable<string> headers)
{
    return headers
        .Where(header => !string.IsNullOrWhiteSpace(header))
        .Select(header => header.Trim())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
}
