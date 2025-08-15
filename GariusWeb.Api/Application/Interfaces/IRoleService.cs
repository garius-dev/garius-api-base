using GariusWeb.Api.Application.Dtos.Auth;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IRoleService
    {
        Task<List<string>> GetRolesAsync(CancellationToken cancellationToken = default);

        Task<List<string>> GetUserRolesAsync(string userEmail, CancellationToken cancellationToken = default);

        Task CreateRoleAsync(CreateRoleRequest request);

        Task AddRoleToUserAsync(UserRoleRequest request, CancellationToken cancellationToken = default);

        Task UpdateUserRoleAsync(UserRoleRequest request, CancellationToken cancellationToken = default);

        Task RemoveAllRolesFromUserAsync(UserEmailRequest request, CancellationToken cancellationToken = default);
    }
}