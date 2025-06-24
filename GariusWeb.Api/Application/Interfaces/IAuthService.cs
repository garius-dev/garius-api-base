

using GariusWeb.Api.Application.Dtos.Auth;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IAuthService
    {
        Task RegisterAsync(RegisterRequest request);
        Task<string> LoginAsync(LoginRequest request);
        Task ConfirmEmailAsync(string userId, string token);
        Task ForgotPasswordAsync(ForgotPasswordRequest request);
        Task ResetPasswordAsync(ResetPasswordRequest request);
    }
}
