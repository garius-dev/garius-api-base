using GariusWeb.Api.Application.Dtos.UserAndRoles;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Abstractions;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Domain.Interfaces;
using Microsoft.AspNetCore.Identity;
using System.Linq.Expressions;

namespace GariusWeb.Api.Application.Services
{
    public class UserService : IUserService
    {
        private readonly IGenericRepository<ApplicationUser> _userRepository;
        private readonly UserManager<ApplicationUser> _userManager;

        public UserService(IGenericRepository<ApplicationUser> userRepository, UserManager<ApplicationUser> userManager)
        {
            _userRepository = userRepository;
            _userManager = userManager;
        }

        public async Task<PagedResult<UserDetailsDto>> GetUsersPagedAsync(int pageSize, string? lastId, string? searchTerm, CancellationToken cancellationToken)
        {
            Guid? lastGuid = null;
            if (!string.IsNullOrEmpty(lastId) && Guid.TryParse(lastId, out var parsedGuid))
            {
                lastGuid = parsedGuid;
            }

            Expression<Func<ApplicationUser, bool>>? filter = null;
            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                var normalizedSearchTerm = searchTerm.ToUpper();
                filter = u => (u.NormalizedFullName != null && u.NormalizedFullName.Contains(normalizedSearchTerm)) ||
                               (u.NormalizedEmail != null && u.NormalizedEmail.Contains(normalizedSearchTerm));
            }

            var pagedResult = await _userRepository.GetPagedAsync(pageSize, lastGuid, filter, cancellationToken);

            var userDtos = new List<UserDetailsDto>();
            foreach (var user in pagedResult.Items)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userDtos.Add(new UserDetailsDto
                {
                    Id = user.Id.ToString(),
                    UserName = user.Fullname ?? string.Empty,
                    Email = user.Email ?? string.Empty,
                    Roles = roles
                });
            }

            return new PagedResult<UserDetailsDto>
            {
                Items = userDtos,
                TotalCount = pagedResult.TotalCount,
                HasNextPage = pagedResult.HasNextPage
            };
        }


    }
}
