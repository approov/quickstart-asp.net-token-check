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
builder.Services.Configure<AppSettings>(appSettings => {
    appSettings.ApproovSecretBytes = approovSecretBytes;
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

app.UseAuthorization();

app.MapControllers();

app.Run();
