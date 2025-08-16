using GariusWeb.Api.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace GariusWeb.Api.Helpers
{
    public class HealthCheckHelper : IHealthCheck
    {
        private readonly IConfiguration _config;

        public HealthCheckHelper(IConfiguration config)
        {
            _config = config;
        }

        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            var appConfig = new
            {
                env = _config["ASPNETCORE_ENVIRONMENT"],
                enableHttpsRedirect = _config["HTTPS_REDIRECTION_ENABLED"].ToBoolean(),
                enableDebugEndpoints = _config["DEV_ENDPOINTS_ENABLED"].ToBoolean(),
                enableSwagger = _config["SWAGGER_ENABLED"].ToBoolean()
            };

            string connDb = _config[$"ConnectionStringSettings:{appConfig.env}"].MaskConnectionString();
            string connRedis = _config[$"RedisSettings:{appConfig.env}:Configuration"] ?? "UNKNOWN";

            return Task.FromResult(
            HealthCheckResult.Healthy("UP", new Dictionary<string, object>
            {
                { "env", appConfig.env! },
                { "enableHttpsRedirect", appConfig.enableHttpsRedirect! },
                { "enableDebugEndpoints", appConfig.enableDebugEndpoints! },
                { "enableSwagger", appConfig.enableSwagger! },
                { "connDb", connDb! },
                { "connRedis", connRedis! },
            }));
        }
    }
}
