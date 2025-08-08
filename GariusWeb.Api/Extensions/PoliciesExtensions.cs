using Microsoft.AspNetCore.Authorization;

namespace GariusWeb.Api.Extensions
{
    public static class PoliciesExtensions
    {
        //public const string RequireDashboardWriteClaim = "RequireDashboardWriteClaim";
        public static void ConfigurePolicies(AuthorizationOptions options)
        {
            options.AddPolicy("LoggedInOnly", policy => policy.RequireAuthenticatedUser());

            // Policy baseada em Claim
            //options.AddPolicy(RequireDashboardWriteClaim, policy =>
            //    policy.RequireClaim("dashboard", "can-write").RequireAuthenticatedUser());
        }
    }
}
