using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class RateLimitExceededException : BaseException
    {
        public RateLimitExceededException(string message = "Limite de requisições excedido")
            : base(message, HttpStatusCode.TooManyRequests) { }
    }
}
