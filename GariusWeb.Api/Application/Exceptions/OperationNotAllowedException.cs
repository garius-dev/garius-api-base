using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class OperationNotAllowedException : BaseException
    {
        public OperationNotAllowedException(string message = "Operação não permitida")
            : base(message, HttpStatusCode.MethodNotAllowed) { }
    }
}
