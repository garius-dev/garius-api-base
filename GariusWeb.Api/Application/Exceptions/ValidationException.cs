using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class ValidationException : BaseException
    {
        public ValidationException(string message)
            : base(message, HttpStatusCode.BadRequest) { }
    }
}
