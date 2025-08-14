using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class CodeExchangeRequest
    {
        [Required(ErrorMessage = "O código é obrigatório.")]
        public string Code { get; set; } = string.Empty;
    }
}
