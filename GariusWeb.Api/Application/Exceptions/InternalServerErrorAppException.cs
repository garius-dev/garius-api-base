using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class InternalServerErrorAppException : BaseException
    {
        public InternalServerErrorAppException(string message = "Erro interno no servidor")
            : base(message, HttpStatusCode.InternalServerError) { }
    }
}
