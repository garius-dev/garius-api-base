using AngleSharp.Io;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace GariusWeb.Api.Infrastructure.Middleware
{
    public class CustomAuthorizationMiddleware : IAuthorizationMiddlewareResultHandler
    {
        private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

        public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
        {
            if (authorizeResult.Succeeded)
            {
                await next(context);
                return;
            }

            var response = new ApiResponse<string>
            {
                Success = false,
                StatusCode = authorizeResult.Forbidden ? 403 : 401,
                Message = authorizeResult.Forbidden
                ? "Você não tem permissão para acessar este recurso."
                : "Você precisa estar autenticado para acessar este recurso.",
                Data = null
            };

            context.Response.StatusCode = response.StatusCode;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(response);
        }
    }
}
