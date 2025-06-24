using System.Net;

namespace GariusWeb.Api.Application.Exceptions
{
    public class ConflictException : BaseException
    {
        public ConflictException(string message = "Conflito de dados")
            : base(message, HttpStatusCode.Conflict) { }
    }
}
