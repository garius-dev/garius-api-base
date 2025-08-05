using Microsoft.AspNetCore.Authentication;

namespace GariusWeb.Api.Helpers
{
    public class ExternalAuthUrlHelper
    {
        public static string GetExternalAuthenticationUrl(HttpContext httpContext, string provider, string redirectUrl)
        {
            // Cria as propriedades de autenticação externa
            var properties = new AuthenticationProperties
            {
                RedirectUri = redirectUrl
            };

            // O AuthenticationScheme normalmente é o nome do provider: "Google", "Microsoft"
            // O endpoint padrão de challenge é "/signin/{provider}"
            // Mas normalmente o middleware responde em "/signin-{provider}", então a URL para redirecionar é:
            // "/api/v1/auth/external-login/{provider}?redirectUrl=..."

            // Gere o endpoint relativo
            var challengeUrl = $"/api/v1/auth/external-login/{provider}?transitionUrl={Uri.EscapeDataString(redirectUrl)}";

            // Monte a URL absoluta com base no contexto
            var request = httpContext.Request;
            var baseUrl = $"{request.Scheme}://{request.Host}";
            return baseUrl + challengeUrl;
        }
    }
}
