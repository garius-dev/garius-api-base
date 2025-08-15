using GariusWeb.Api.Application.Dtos.UserAndRoles;
using GariusWeb.Api.Domain.Abstractions;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IUserService
    {
        Task<PagedResult<UserDetailsDto>> GetUsersPagedAsync(int pageSize, string? lastId, string? searchTerm, CancellationToken cancellationToken);
    }
}
