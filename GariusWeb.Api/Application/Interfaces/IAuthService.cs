

using GariusWeb.Api.Application.Dtos;
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
        Task ConfirmEmailAsync(string userId, string token);
        Task ForgotPasswordAsync(ForgotPasswordRequest request);
        Task ResetPasswordAsync(ResetPasswordRequest request);
        Task<bool> CreateRoleIfNotExistsAsync(CreateRoleRequest request);
        Task<List<string>> GetRolesAsync();
        Task<List<string>> GetUserRoles(string userEmail);
        Task<bool> AddRoleToUserAsync(string userEmail, string roleName);
        Task<bool> RemoveRoleFromUserAsync(string userEmail, string roleName);
        Task<bool> UpdateUserRoleAsync(string userEmail, string newRoleName);

        Task<PagedResult<UserRoleResponse>> GetUsersWithRolesAsync(string? search, int page = 1, int pageSize = 20);
    }
}
