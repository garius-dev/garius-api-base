using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class UnauthorizedAccessAppException : BaseException
    {
        public UnauthorizedAccessAppException(string message = "Acesso não autorizado")
            : base(message, HttpStatusCode.Unauthorized) { }
    }
}
