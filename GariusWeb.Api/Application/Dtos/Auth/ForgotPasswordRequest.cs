using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = default!;
    }
}
