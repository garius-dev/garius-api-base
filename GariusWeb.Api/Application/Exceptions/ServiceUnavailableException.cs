using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class ServiceUnavailableException : BaseException
    {
        public ServiceUnavailableException(string message = "Serviço temporariamente indisponível")
            : base(message, HttpStatusCode.ServiceUnavailable) { }
    }
}
