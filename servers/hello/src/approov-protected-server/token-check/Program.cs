using Hello.Helpers;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

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
var tokenBindingHeader = DotNetEnv.Env.GetString("APPROOV_TOKEN_BINDING_HEADER");
var signatureRequireCreated = ReadBoolean(DotNetEnv.Env.GetString("APPROOV_SIGNATURE_REQUIRE_CREATED"), true);
var signatureRequireExpires = ReadBoolean(DotNetEnv.Env.GetString("APPROOV_SIGNATURE_REQUIRE_EXPIRES"), false);
var signatureMaxAge = ReadTimeSpanFromSeconds(DotNetEnv.Env.GetString("APPROOV_SIGNATURE_MAX_AGE_SECONDS"));
var signatureClockSkew = ReadTimeSpanFromSeconds(DotNetEnv.Env.GetString("APPROOV_SIGNATURE_CLOCK_SKEW_SECONDS")) ?? TimeSpan.Zero;
var tokenBindingHeaders = ParseHeaderList(tokenBindingHeader);
builder.Services.Configure<AppSettings>(appSettings =>
{
    appSettings.ApproovSecretBytes = approovSecretBytes;
    appSettings.TokenBindingHeaders = tokenBindingHeaders.ToList();
});
builder.Services.Configure<MessageSignatureValidationOptions>(options =>
{
    options.RequireCreated = signatureRequireCreated;
    options.RequireExpires = signatureRequireExpires;
    options.MaximumSignatureAge = signatureMaxAge;
    options.AllowedClockSkew = signatureClockSkew;
});
builder.Services.AddSingleton<ApproovMessageSignatureVerifier>();

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
app.UseMiddleware<Hello.Middleware.ApproovTokenBindingMiddleware>();
app.UseMiddleware<Hello.Middleware.MessageSigningMiddleware>();

app.UseAuthorization();

app.MapControllers();

app.Run();

static bool ReadBoolean(string? value, bool defaultValue)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return defaultValue;
    }

    if (bool.TryParse(value, out var parsed))
    {
        return parsed;
    }

    return defaultValue;
}

static TimeSpan? ReadTimeSpanFromSeconds(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return null;
    }

    if (double.TryParse(value, NumberStyles.Any, CultureInfo.InvariantCulture, out var seconds) && seconds >= 0)
    {
        return TimeSpan.FromSeconds(seconds);
    }

    return null;
}

static IList<string> ParseHeaderList(string? raw)
{
    if (string.IsNullOrWhiteSpace(raw))
    {
        return new List<string>();
    }

    return raw
        .Split(',', StringSplitOptions.RemoveEmptyEntries)
        .Select(value => value.Trim())
        .Where(value => value.Length > 0)
        .ToList();
}
