using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class NotFoundException : BaseException
    {
        public NotFoundException(string resource = "Recurso")
            : base($"{resource} não encontrado.", HttpStatusCode.NotFound) { }
    }
}
