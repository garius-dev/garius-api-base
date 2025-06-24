using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class ForbiddenAccessException : BaseException
    {
        public ForbiddenAccessException(string message = "Você não tem permissão para acessar este recurso.")
            : base(message, HttpStatusCode.Forbidden) { }
    }
}
