using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Helpers;
using System.Text.Json;

namespace GariusWeb.Api.Infrastructure.Middleware
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;

        public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (BaseException ex)
            {
                _logger.LogWarning(ex, "Exceção de domínio");

                context.Response.ContentType = "application/json";
                context.Response.StatusCode = (int)ex.StatusCode;

                var response = ApiResponse<string>.Fail(ex.Message, context.Response.StatusCode);
                var result = JsonSerializer.Serialize(response);

                await context.Response.WriteAsync(result);
            }
        }
    }
}
