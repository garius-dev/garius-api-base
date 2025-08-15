using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;
using System.Security.Claims;

namespace GariusWeb.Api.WebApi.Dev
{
    public static class DevEndpointExtensions
    {
        public static IEndpointRouteBuilder MapDevEndpoints(this IEndpointRouteBuilder app)
        {
            var env = app.ServiceProvider.GetRequiredService<IHostEnvironment>();
            if (!env.IsDevelopment()) return app;

            var cfg = app.ServiceProvider.GetRequiredService<IConfiguration>();
            var enabled = cfg.GetValue("DEV_ENDPOINTS_ENABLED", true);
            if (!enabled) return app;

            var group = app.MapGroup("/dev")
                       .WithTags("Dev");

            // --- CRIAÇÃO DO ENDPOINT DE TESTE DE PING DO REDIS ---
            group.MapGet("/redis/ping", async (IDistributedCache cache) =>
            {
                const string key = "cache-teste";
                var valor = await cache.GetStringAsync(key);

                if (valor != null)
                    return Results.Ok(new { valor, deCache = true });

                valor = $"Gerado em {DateTime.Now}";
                await cache.SetStringAsync(key, valor, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(30)
                });

                return Results.Ok(new { valor, deCache = false });
            });

            group.MapPost("/seed/developer", async (
                HttpRequest http,
                UserManager<ApplicationUser> users,
                RoleManager<ApplicationRole> roles,
                IJwtTokenGenerator jwtGenerator) =>
            {
                var email = http.Query["email"].ToString();
                var username = http.Query["username"].ToString();
                var password = http.Query["password"].ToString();

                if (string.IsNullOrWhiteSpace(email)) email = "dev.tester@example.local";
                if (string.IsNullOrWhiteSpace(username)) username = "dev.tester";
                if (string.IsNullOrWhiteSpace(password)) password = "Dev!12345";

                var devRoleName = GetDeveloperRoleName();

                if (!await roles.RoleExistsAsync(devRoleName))
                {
                    var roleCreate = await roles.CreateAsync(new ApplicationRole
                    {
                        Id = Guid.NewGuid(),
                        Name = devRoleName,
                        NormalizedName = devRoleName.ToUpperInvariant()
                    });

                    if (!roleCreate.Succeeded)
                    {
                        throw new BadRequestException("Falha ao criar role Developer");
                    }
                }

                var user = await users.FindByEmailAsync(email);
                if (user is null)
                {
                    user = new ApplicationUser
                    {
                        Id = Guid.NewGuid(),
                        FirstName = "Dev",
                        LastName = "Tester",
                        Email = email,
                        UserName = username,
                        EmailConfirmed = true,
                        PhoneNumberConfirmed = true,
                        LockoutEnabled = false
                    };
                    user.Fullname = $"{user.FirstName} {user.LastName}";
                    user.NormalizedFullName = user.Fullname.ToUpperInvariant();

                    var create = await users.CreateAsync(user, password);

                    if (!create.Succeeded)
                    {
                        throw new BadRequestException("Falha ao criar usuário de teste.");
                    }
                }

                if (!await users.IsInRoleAsync(user, devRoleName))
                {
                    var addRole = await users.AddToRoleAsync(user, devRoleName);
                    if (!addRole.Succeeded)
                    {
                        throw new BadRequestException("Falha ao adicionar role Developer.");
                    }
                }

                string token;

                var extraClaims = new List<Claim>
                {
                    new("dev-seed", "true")
                };

                token = jwtGenerator.GenerateToken(user, new List<string> { devRoleName }, extraClaims);

                return Results.Ok(ApiResponse<string>.Ok(token, "Sucesso!"));
            });

            group.MapDelete("/seed/developer", async (
                HttpRequest http,
                UserManager<ApplicationUser> users) =>
            {
                var email = http.Query["email"].ToString();
                if (string.IsNullOrWhiteSpace(email)) email = "dev.tester@example.local";

                var user = await users.FindByEmailAsync(email);
                if (user is null)
                    return Results.Ok(ApiResponse<string>.Ok("Usuário não existe (ok)."));

                var del = await users.DeleteAsync(user);
                if (!del.Succeeded)
                {
                    throw new BadRequestException("Falha ao remover o usuário de teste.");
                }

                return Results.Ok(ApiResponse<string>.Ok("Usuário de teste removido."));
            });

            return app;
        }

        private static string GetDeveloperRoleName()
        {
            return "Developer";
        }
    }
}