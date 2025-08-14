using GariusWeb.Api.Application.Exceptions;
using System.Threading.RateLimiting;

namespace GariusWeb.Api.Extensions
{    
    public static class RateLimiterExtensions
    {
        public const string LoginPolicy = "LoginPolicy";
        public const string RegisterPolicy = "RegisterPolicy";

        public static IServiceCollection AddCustomRateLimiter(this IServiceCollection services)
        {
            services.AddRateLimiter(options =>
            {
                // Política global: aplica para toda a API se nenhum perfil for especificado
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
                {
                    var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: ip,
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 100, // 100 req/minuto por IP (ajuste conforme necessário)
                            Window = TimeSpan.FromMinutes(1),
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 0
                        });
                });

                // Política específica para login
                options.AddPolicy(LoginPolicy, context =>
                {
                    var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    return RateLimitPartition.GetTokenBucketLimiter(
                        partitionKey: ip,
                        factory: _ => new TokenBucketRateLimiterOptions
                        {
                            TokenLimit = 5, // 5 tentativas por minuto
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 0,
                            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                            TokensPerPeriod = 5,
                            AutoReplenishment = true
                        });
                });

                // Política para registro de usuário
                options.AddPolicy(RegisterPolicy, context =>
                {
                    var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    return RateLimitPartition.GetTokenBucketLimiter(
                        partitionKey: ip,
                        factory: _ => new TokenBucketRateLimiterOptions
                        {
                            TokenLimit = 3, // 3 registros por minuto
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 0,
                            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                            TokensPerPeriod = 3,
                            AutoReplenishment = true
                        });
                });

                options.OnRejected = (context, token) =>
                {
                    // Aqui você lança a sua exception personalizada
                    throw new RateLimitExceededException("Limite de requisições excedido. Tente novamente mais tarde.");
                };
            });

            return services;
        }
    }
}
