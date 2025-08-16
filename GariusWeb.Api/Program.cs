using Asp.Versioning;
using Asp.Versioning.ApiExplorer;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Application.Services;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Domain.Interfaces;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Helpers;
using GariusWeb.Api.Infrastructure.Data;
using GariusWeb.Api.Infrastructure.Data.Repositories;
using GariusWeb.Api.Infrastructure.Middleware;
using GariusWeb.Api.Infrastructure.Services;
using GariusWeb.Api.Swagger;
using GariusWeb.Api.WebApi.Dev;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using StackExchange.Redis;
using System.Text;
using System.Text.Json;
using static GariusWeb.Api.Configuration.AppSecrets;

//Add-Migration AddUsersSearchIndex -Context ApplicationDbContext

var builder = WebApplication.CreateBuilder(args);

// --- CONFIGURAÇÃO DAS VARIÁVEIS DE AMBIENTE ---
var enableHttpsRedirect =
    builder.Configuration.GetValue<bool?>("HTTPS_REDIRECTION_ENABLED") ?? true;

bool enableDebugEndpoints =
    builder.Configuration.GetValue<bool?>("DEV_ENDPOINTS_ENABLED") ?? false;

bool enableSwagger =
    builder.Configuration.GetValue<bool?>("SWAGGER_ENABLED") ?? false;

bool migrateOnly =
    builder.Configuration.GetValue<bool?>("MIGRATE_ONLY") ?? false;

// --- CONFIGURAÇÃO DO LOG ---
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

if (builder.Environment.IsDevelopment())
{
    Serilog.Debugging.SelfLog.Enable(m => Console.Error.WriteLine(m));
}

builder.Host.UseSerilog((ctx, services, lc) => lc
    .ReadFrom.Configuration(ctx.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("app", "garius-api")
    .Enrich.WithProperty("env", ctx.HostingEnvironment.EnvironmentName));

// --- CONFIGURAÇÃO DO GOOGLE SECRETS ---
var secretConfig = builder.AddGoogleSecrets("GariusTechAppSecrets");

// --- ADICIONA O GOOGLE SECRETS À CONFIGURAÇÃO GLOBAL ---
builder.Configuration.AddConfiguration(secretConfig);

// --- CONFIGURAÇÃO DE CONEXÃO DO REDIS E DB ---
var redisConfig = builder.Configuration[$"RedisSettings:{builder.Environment.EnvironmentName}:Configuration"];
var connectionString = builder.Configuration[$"ConnectionStringSettings:{builder.Environment.EnvironmentName}"];

if (string.IsNullOrEmpty(connectionString))
{
    Log.Fatal("DB: GET CONNECTION FAILED.");
    Log.CloseAndFlush();
    Environment.Exit(1);
}

if (string.IsNullOrWhiteSpace(redisConfig))
{
    Log.Fatal("REDIS: GET CONNECTION FAILED.");
    Log.CloseAndFlush();
    Environment.Exit(1);
}

// --- CONFIGURAÇÃO DO RATE LIMITER ---
builder.Services.AddCustomRateLimiter();

// --- CONFIGURAÇÃO DO CORS ---
builder.Services.AddCustomCors(builder.Environment);

// --- CONFIGURAÇÃO DO SWAGGER ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.ConfigureOptions<ConfigureSwaggerOptions>();

// --- CONFIGURAÇÃO DO VERSIONAMENTO DO SWAGGER ---
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

// --- LOAD DAS SECRETS ---
builder.Services.AddValidatedSettings<ConnectionStringSettings>(builder.Configuration, "ConnectionStringSettings");
builder.Services.AddValidatedSettings<GoogleExternalAuthSettings>(builder.Configuration, "GoogleExternalAuthSettings");
builder.Services.AddValidatedSettings<MicrosoftExternalAuthSettings>(builder.Configuration, "MicrosoftExternalAuthSettings");
builder.Services.AddValidatedSettings<CloudflareSettings>(builder.Configuration, "CloudflareSettings");
builder.Services.AddValidatedSettings<CloudinarySettings>(builder.Configuration, "CloudinarySettings");
builder.Services.AddValidatedSettings<ResendSettings>(builder.Configuration, "ResendSettings");
builder.Services.AddValidatedSettings<JwtSettings>(builder.Configuration, "JwtSettings");
builder.Services.AddValidatedSettings<RedisSettings>(builder.Configuration, "RedisSettings");

// --- CONFIGURAÇÃO DO REDIS ---
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = redisConfig;
    options.InstanceName = "Garius:";
});

// --- CONFIGURAÇÃO DO BANCO DE DADOS ---
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString, npgsqlOptionsAction: sqlOptions =>
    {
        sqlOptions.EnableRetryOnFailure(
            maxRetryCount: 5,
            maxRetryDelay: TimeSpan.FromSeconds(30),
            errorCodesToAdd: null);
    }));

// --- CONFIGURAÇÃO DO USER IDENTITY ---
builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>(options =>
    {
        // Configurações de senha
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 6;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireLowercase = true;
        options.Password.RequiredUniqueChars = 1;

        // Configurações de Lockout
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;

        // Configurações de usuário
        options.User.AllowedUserNameCharacters =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
        options.User.RequireUniqueEmail = true;

        // Configurações de SignIn
        options.SignIn.RequireConfirmedAccount = true;
        options.SignIn.RequireConfirmedEmail = true;
        options.SignIn.RequireConfirmedPhoneNumber = false;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// --- CONFIGURAÇÃO DOS COOKIES DE AUTENTICAÇÃO ---
builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.ExternalScheme, options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/api/v1/auth/login";
    options.AccessDeniedPath = "/api/v1/auth/access-denied";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.ConfigureExternalCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var jwtConfig = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>()!;
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
.AddGoogle("Google", options =>
{
    var google = builder.Configuration.GetSection("GoogleExternalAuthSettings").Get<GoogleExternalAuthSettings>()!;
    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
    options.ClientId = google.ClientId;
    options.ClientSecret = google.ClientSecret;
    options.SaveTokens = true;
    options.CallbackPath = "/signin-google";
    options.Scope.Add("profile");
    options.Scope.Add("email");
})
.AddMicrosoftAccount("Microsoft", options =>
{
    var ms = builder.Configuration.GetSection("MicrosoftExternalAuthSettings").Get<MicrosoftExternalAuthSettings>()!;
    options.ClientId = ms.ClientId;
    options.ClientSecret = ms.ClientSecret;
    options.SaveTokens = true;
    options.CallbackPath = "/signin-microsoft";
    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
});

// --- CONFIGURAÇÃO DO HEALTH CHECK ---
builder.Services.AddHealthChecks()
    .AddCheck<HealthCheckHelper>("config")
    .AddNpgSql(connectionString, name: "PostgreSQL",
               failureStatus: HealthStatus.Unhealthy,
               tags: new[] { "db" })
    .AddRedis(redisConfig, name: "Redis",
              failureStatus: HealthStatus.Unhealthy,
              tags: new[] { "cache" })
    .AddCheck("self", () => HealthCheckResult.Healthy("UP"));

// --- CONFIGURAÇÃO DOS HEADERS DE SEGURANÇA ---
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// --- CONFIGURAÇÃO DO DATA PROTECTION ---
var mux = ConnectionMultiplexer.Connect(redisConfig);
builder.Services
    .AddDataProtection()
    .SetApplicationName("Garius.Api")
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
    .PersistKeysToStackExchangeRedis(mux, "DataProtection-Keys");

// --- CONFIGURAÇÃO DOS CONTROLLERS ---
builder.Services.AddControllers()
    .ConfigureApiBehaviorOptions(options =>
    {
        options.SuppressModelStateInvalidFilter = true;
    })
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.DictionaryKeyPolicy = JsonNamingPolicy.CamelCase;
    });

// ### INJEÇÃO DE DEPENDÊNCIAS ###

// --- CONFIGURAÇÃO DO RESEND ---
builder.Services.AddHttpClient<IEmailSender, ResendEmailSender>();

// --- CONFIGURAÇÃO DE SERVIÇOS DE TOKEN ---
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();

// --- CONFIGURAÇÃO DE SERVIÇOS DE AUTENTICAÇÃO ---
builder.Services.AddScoped<IAuthService, AuthService>();

// --- CONFIGURAÇÃO DE SERVIÇOS DE ROLES ---
builder.Services.AddScoped<IRoleService, RoleService>();

// --- CONFIGURAÇÃO DE USUÁRIOS ---
builder.Services.AddScoped<IUserService, UserService>();

// --- CONFIGURAÇÃO FO REPOSITÓRIO GENÉRICO DE BUSCA ---
builder.Services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));

// --- CONFIGURAÇÃO DE SERVIÇOS DE CUSTOMIZAÇÃO DO AUTHORIZE ---
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, CustomAuthorizationMiddleware>();

// --- CONFIGURAÇÃO DE SERVIÇOS DO REDIS ---
builder.Services.AddSingleton<ICacheService, RedisCacheService>();

// --- CONFIGURAÇÃO DO HELPER PARA COLETAR DADOS DE USUÁRIO LOGADO ---
builder.Services.AddScoped<LoggedUserHelper>();

// --- CONFIGURAÇÃO DE SERVIÇOS DE CUSTOMIZAÇÃO DAS POLICES ---
builder.Services.AddAuthorization(options =>
{
    PoliciesExtensions.ConfigurePolicies(options);
});

var app = builder.Build();

// --- CONFIGURAÇÃO DO LOG DE REQUISIÇÕES ---
app.UseSerilogRequestLogging(o =>
{
    o.EnrichDiagnosticContext = (d, ctx) =>
    {
        d.Set("RequestPath", ctx.Request.Path);
        d.Set("ClientIP", ctx.Connection.RemoteIpAddress?.ToString() ?? "UNKNOWN");
        d.Set("XForwardedFor", ctx.Request.Headers["X-Forwarded-For"].ToString());
        d.Set("CFConnectingIP", ctx.Request.Headers["CF-Connecting-IP"].ToString());
        d.Set("UserAgent", ctx.Request.Headers.UserAgent.ToString());
        d.Set("StatusCode", ctx.Response?.StatusCode ?? 0);
    };
});

app.UseForwardedHeaders();

// --- CONFIGURAÇÃO DA BUILD DE MIGRATION ---
if (migrateOnly)
{
    using (var scope = app.Services.CreateScope())
    {
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        try
        {
            Log.Information("Running migrations...");
            await context.Database.MigrateAsync();
            Log.Information("Migrations completed successfully.");
        }
        catch (Exception ex)
        {
            Log.Fatal($"Migration failed: {ex.Message}");
            Log.CloseAndFlush();
            Environment.Exit(1);
        }
    }

    Log.CloseAndFlush();
    Environment.Exit(0);
}

Log.Information("-----> OK");

// --- CONFIGURAÇÃO DO MIDDLEWARE DE TRATAMENTO DE EXCEÇÕES ---
app.UseMiddleware<ExceptionHandlingMiddleware>();

// --- CONFIGURAÇÃO DO SWAGGER UI ---
var provider = app.Services.GetRequiredService<IApiVersionDescriptionProvider>();
if (app.Environment.IsDevelopment() || enableSwagger)
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

// --- CONFIGURAÇÃO DOS ENDPOINTS DE DESENVOLVIMENTO ---
app.MapDevEndpoints();

// --- CONFIGURAÇÃO DO PIPELINE DE REQUISIÇÕES ---
app.UseRouting();

app.UseRateLimiter();
app.UseCustomCors();

// --- HABILITA A REDIRECIONA DE HTTP PARA HTTPS ---
if (enableHttpsRedirect)
{
    app.UseHttpsRedirection();
}

// --- CONFIGURAÇÃO DOS HEADERS DE SEGURANÇA ---
var policy = new HeaderPolicyCollection()
    .AddDefaultSecurityHeaders()
    .RemoveServerHeader()
    .AddContentSecurityPolicy(policyBuilder =>
    {
        policyBuilder.AddDefaultSrc().Self();
        policyBuilder.AddScriptSrc().Self();
        policyBuilder.AddStyleSrc().Self().WithNonce();
        policyBuilder.AddImgSrc().Self().Data();
        policyBuilder.AddFontSrc().Self();
        policyBuilder.AddConnectSrc().Self();
        policyBuilder.AddObjectSrc().None();
        policyBuilder.AddFormAction().Self();
        policyBuilder.AddFrameAncestors().None();
    });

app.UseSecurityHeaders(policy);

// --- CONFIGURAÇÃO DA AUTENTICAÇÃO E AUTORIZAÇÃO ---
app.UseAuthentication();
app.UseAuthorization();

// --- CONFIGURAÇÃO DOS CONTROLLERS ---
app.MapControllers();

// --- CRIAÇÃO DO ENDPOINT DE HEALTH CHECK ---
app.MapHealthChecks("/health", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/healthz", new HealthCheckOptions
{
    Predicate = _ => true,
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        var result = System.Text.Json.JsonSerializer.Serialize(new
        {
            status = report.Status.ToString(),
            details = report.Entries.Select(e => new
            {
                key = e.Key,
                status = e.Value.Status.ToString(),
                description = string.IsNullOrEmpty(e.Value.Description)
                    ? e.Value.Status switch
                    {
                        HealthStatus.Healthy => "UP",
                        HealthStatus.Unhealthy => "DOWN",
                        HealthStatus.Degraded => "DEGRADED",
                        _ => "UNKNOWN"
                    }
                    : e.Value.Description,
                data = e.Value.Data
            })
        });
        await context.Response.WriteAsync(result);
    }
});

app.Run();