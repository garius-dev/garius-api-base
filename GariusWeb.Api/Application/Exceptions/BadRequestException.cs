using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class BadRequestException : BaseException
    {
        public BadRequestException(string message = "Requisição inválida")
            : base(message, HttpStatusCode.BadRequest) { }
    }
}
