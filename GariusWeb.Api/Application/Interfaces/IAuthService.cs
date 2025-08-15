using GariusWeb.Api.Application.Dtos.Auth;
using Microsoft.AspNetCore.Mvc;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IAuthService
    {
        Task RegisterAsync(RegisterRequest request);

        Task<string> LoginAsync(LoginRequest request);

        ChallengeResult GetExternalLoginChallangeAsync(string provider, string redirectUrl);

        string GetExternalLoginUrl(string provider, string redirectUrl);

        Task<string> ExternalLoginCallbackAsync(string transitionUrl, string? returnUrl);

        Task<string> ExchangeCode(string code);

        Task ConfirmEmailAsync(string userId, string token);

        Task ForgotPasswordAsync(ForgotPasswordRequest request);

        Task ResetPasswordAsync(ResetPasswordRequest request);
    }
}