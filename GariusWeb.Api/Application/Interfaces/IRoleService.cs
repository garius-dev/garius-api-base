using GariusWeb.Api.Application.Dtos.Auth;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IRoleService
    {
        Task<List<string>> GetRolesAsync();

        Task<List<string>> GetUserRolesAsync(string userEmail);

        Task CreateRoleAsync(CreateRoleRequest request);

        Task AddRoleToUserAsync(UserRoleRequest request);

        Task UpdateUserRoleAsync(UserRoleRequest request);

        Task RemoveAllRolesFromUserAsync(UserEmailRequest request);
    }
}