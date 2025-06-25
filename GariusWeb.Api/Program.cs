using Asp.Versioning;
using Asp.Versioning.ApiExplorer;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Application.Services;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Infrastructure.Data;
using GariusWeb.Api.Infrastructure.Middleware;
using GariusWeb.Api.Infrastructure.Services;
using GariusWeb.Api.Swagger;
using Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using Serilog.Events;
using Swashbuckle.AspNetCore.SwaggerGen;
using System;
using System.Text;
using static GariusWeb.Api.Configuration.AppSecrets;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Debug()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    //.WriteTo.Seq("http://localhost:5341") // Descomente se for usar Seq
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog();

// --- Configura��o do Swagger ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.ConfigureOptions<ConfigureSwaggerOptions>();


// --- Configura��o do Versionamento do Swagger ---
builder.Services.AddApiVersioning(options =>
{
    options.DefaultApiVersion = new ApiVersion(1, 0);
    options.AssumeDefaultVersionWhenUnspecified = true;
    options.ReportApiVersions = true;
    options.ApiVersionReader = new UrlSegmentApiVersionReader();
}).AddApiExplorer(options =>
{
    options.GroupNameFormat = "'v'VVV";
    options.SubstituteApiVersionInUrl = true;
});

// --- Configura��o do Google Secrets ---
var secretConfig = builder.AddGoogleSecrets("GariusTech");

builder.Services.AddValidatedSettings<ConnectionStringSettings>(secretConfig, "ConnectionStringSettings");
builder.Services.AddValidatedSettings<GoogleExternalAuthSettings>(secretConfig, "GoogleExternalAuthSettings");
builder.Services.AddValidatedSettings<MicrosoftExternalAuthSettings>(secretConfig, "MicrosoftExternalAuthSettings");
builder.Services.AddValidatedSettings<CloudflareSettings>(secretConfig, "CloudflareSettings");
builder.Services.AddValidatedSettings<CloudinarySettings>(secretConfig, "CloudinarySettings");
builder.Services.AddValidatedSettings<ResendSettings>(secretConfig, "ResendSettings");
builder.Services.AddValidatedSettings<JwtSettings>(secretConfig, "JwtSettings");

// --- CONFIGURA��O DO BANCO DE DADOS ---
var connectionString = secretConfig.GetSection("ConnectionStringSettings:Default").Value;

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString, npgsqlOptionsAction: sqlOptions =>
    {
        sqlOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorCodesToAdd: null);
    }));

// --- Configura��o do User Identity ---
builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        // Configura��es de senha
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequiredUniqueChars = 1;

        // Configura��es de Lockout
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;

        // Configura��es de usu�rio
        options.User.AllowedUserNameCharacters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
        options.User.RequireUniqueEmail = true;

        // Configura��es de SignIn
        options.SignIn.RequireConfirmedAccount = true;
        options.SignIn.RequireConfirmedEmail = true;
        options.SignIn.RequireConfirmedPhoneNumber = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// --- CONFIGURA��O DO JWT ---
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var jwtConfig = secretConfig.GetSection("JwtSettings").Get<JwtSettings>()!;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtConfig.Issuer,
        ValidAudience = jwtConfig.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig.Secret)),
        ClockSkew = TimeSpan.Zero
    };
})
.AddCookie(options =>
{
    options.LoginPath = "/api/v1/auth/login";
    options.AccessDeniedPath = "/api/v1/auth/access-denied";
})
.AddGoogle("Google", options =>
{
    var google = secretConfig.GetSection("Google").Get<GoogleExternalAuthSettings>()!;
    options.ClientId = google.ClientId;
    options.ClientSecret = google.ClientSecret;
    options.SaveTokens = true;
    options.CallbackPath = "/signin-google";
    options.Scope.Add("profile");
    options.Scope.Add("email");
})
.AddMicrosoftAccount("Microsoft", options =>
{
    var ms = secretConfig.GetSection("Microsoft").Get<MicrosoftExternalAuthSettings>()!;
    options.ClientId = ms.ClientId;
    options.ClientSecret = ms.ClientSecret;
    options.SaveTokens = true;
    options.CallbackPath = "/signin-microsoft";
});

// --- CONFIGURA��O DO RESEND ---
builder.Services.AddHttpClient<IEmailSender, ResendEmailSender>();

// --- CONFIGURA��O DE SERVI�OS DE AUTENTICA��O ---
builder.Services.AddScoped<IAuthService, AuthService>();

// --- CONFIGURA��O DO CORS ---
builder.Services.AddCustomCors(builder.Environment);

// --- Add services to the container ---
builder.Services.AddControllers();

var app = builder.Build();

// --- Configura��o dos Middlewares ---
app.UseMiddleware<ExceptionHandlingMiddleware>();

// --- Configure the HTTP request pipeline ---
var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        foreach (var description in provider.ApiVersionDescriptions)
        {
            options.SwaggerEndpoint($"/swagger/{description.GroupName}/swagger.json",
                $"GariusWeb.Api {description.GroupName.ToUpper()}");
        }

        options.RoutePrefix = "swagger";
        options.DefaultModelExpandDepth(-1);
    });
}

app.UseHttpsRedirection();

app.UseCustomCors();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
