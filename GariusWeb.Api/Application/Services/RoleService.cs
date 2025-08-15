using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace GariusWeb.Api.Application.Services
{
    public class RoleService : IRoleService
    {
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly LoggedUserHelper _loggedUserHelper;
        private readonly ILogger<RoleService> _logger;

        public RoleService(
            RoleManager<ApplicationRole> roleManager,
            UserManager<ApplicationUser> userManager,
            LoggedUserHelper loggedUserHelper,
            ILogger<RoleService> logger)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _loggedUserHelper = loggedUserHelper;
            _logger = logger;
        }

        private class UserInfo
        {
            public ApplicationUser User { get; set; } = default!;
            public IList<string> Roles { get; set; } = new List<string>();
            public int TopRoleLevel { get; set; } = int.MaxValue;
        }

        public async Task CreateRoleAsync(CreateRoleRequest request)
        {
            if (request is null)
                throw new BadRequestException("Requisição inválida.");

            var roleName = NormalizeRoleName(request.RoleName);
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();

            // Regra: pode criar apenas roles com nível >= ao seu (nunca superiores).
            EnsureCanCreateOrAssignRole(loggedUserInfo.TopRoleLevel, request.RoleLevel);

            var roleExists = await _roleManager.RoleExistsAsync(roleName);
            if (roleExists)
                throw new ConflictException($"A role '{roleName}' já existe.");

            var result = await _roleManager.CreateAsync(new ApplicationRole(roleName, null, request.RoleLevel));
            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao criar a role: " + GetErrors(result));

            _logger.LogInformation("Role {RoleName} (Level {Level}) criada por UserId {UserId}.",
                roleName, request.RoleLevel, loggedUserInfo.UserId.ToString());
        }

        public async Task<List<string>> GetRolesAsync(CancellationToken cancellationToken = default)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();

            return await _roleManager.Roles
                .AsNoTracking()
                .Where(r => r.Level >= loggedUserInfo.TopRoleLevel)
                .OrderBy(r => r.Level).ThenBy(r => r.Name)
                .Select(r => r.Name!)
                .ToListAsync(cancellationToken);
        }

        public async Task<List<string>> GetUserRolesAsync(string userEmail, CancellationToken cancellationToken = default)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();
            var targetUserDetails = await FindUserDetailsByEmailAsync(userEmail, cancellationToken);

            // Regra: só pode visualizar/gerenciar quem tem nível estritamente superior (menor número).
            EnsureCanViewOrManageUser(loggedUserInfo.TopRoleLevel, targetUserDetails.TopRoleLevel);

            return targetUserDetails.Roles.ToList();
        }

        public async Task AddRoleToUserAsync(UserRoleRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null)
                throw new BadRequestException("Requisição inválida.");

            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();
            var targetUserDetails = await FindUserDetailsByEmailAsync(request.Email, cancellationToken);

            if (targetUserDetails.Roles.Any())
                throw new ConflictException("Usuário já possui uma role. Utilize a rota de atualização.");

            var roleToAdd = await FindRoleByNameAsync(request.RoleName);

            // Regra: só pode atribuir roles com nível >= ao seu (nunca superiores).
            EnsureCanCreateOrAssignRole(loggedUserInfo.TopRoleLevel, roleToAdd.Level);

            var result = await _userManager.AddToRoleAsync(targetUserDetails.User, roleToAdd.Name!);
            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao adicionar role ao usuário: " + GetErrors(result));

            _logger.LogInformation("Role {RoleName} atribuída ao usuário {TargetUserId} por UserId {UserId}.",
                roleToAdd.Name, targetUserDetails.User.Id, loggedUserInfo.UserId);
        }

        public async Task UpdateUserRoleAsync(UserRoleRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null)
                throw new BadRequestException("Requisição inválida.");

            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();
            var targetUserDetails = await FindUserDetailsByEmailAsync(request.Email, cancellationToken);

            EnsureCanViewOrManageUser(loggedUserInfo.TopRoleLevel, targetUserDetails.TopRoleLevel);

            var newRole = await FindRoleByNameAsync(request.RoleName);

            // Regra: só pode atribuir roles com nível >= ao seu (nunca superiores).
            EnsureCanCreateOrAssignRole(loggedUserInfo.TopRoleLevel, newRole.Level);

            if (targetUserDetails.Roles.Contains(newRole.Name!))
                throw new ConflictException("O usuário já possui esta role.");

            var removeResult = await _userManager.RemoveFromRolesAsync(targetUserDetails.User, targetUserDetails.Roles);
            if (!removeResult.Succeeded)
                throw new InternalServerErrorAppException("Erro ao remover roles antigas: " + GetErrors(removeResult));

            var addResult = await _userManager.AddToRoleAsync(targetUserDetails.User, newRole.Name!);
            if (!addResult.Succeeded)
                throw new InternalServerErrorAppException("Erro ao adicionar a nova role: " + GetErrors(addResult));

            _logger.LogInformation("Roles do usuário {TargetUserId} foram atualizadas para {RoleName} por UserId {UserId}.",
                targetUserDetails.User.Id, newRole.Name, loggedUserInfo.UserId);
        }

        public async Task RemoveAllRolesFromUserAsync(UserEmailRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null)
                throw new BadRequestException("Requisição inválida.");

            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();
            var targetUserDetails = await FindUserDetailsByEmailAsync(request.Email, cancellationToken);
            if (!targetUserDetails.Roles.Any()) return;

            EnsureCanViewOrManageUser(loggedUserInfo.TopRoleLevel, targetUserDetails.TopRoleLevel);

            var result = await _userManager.RemoveFromRolesAsync(targetUserDetails.User, targetUserDetails.Roles);
            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao remover as roles do usuário: " + GetErrors(result));

            _logger.LogInformation("Todas as roles removidas do usuário {TargetUserId} por UserId {UserId}.",
                targetUserDetails.User.Id, loggedUserInfo.UserId);
        }

        //HELPERS
        private static string NormalizeEmail(string email) =>
            (email ?? string.Empty).Trim().ToUpperInvariant();

        private static string NormalizeRoleName(string roleName) =>
            (roleName ?? string.Empty).Trim();

        private static void EnsureCanCreateOrAssignRole(int loggedTopLevel, int targetRoleLevel)
        {
            if (targetRoleLevel < loggedTopLevel)
                throw new UnauthorizedAccessAppException("Você não tem permissão para criar/atribuir uma role superior à sua.");
        }

        private static void EnsureCanViewOrManageUser(int loggedTopLevel, int targetTopLevel)
        {
            if (loggedTopLevel >= targetTopLevel)
                throw new UnauthorizedAccessAppException("Você não tem permissão para visualizar/gerenciar este usuário.");
        }

        private async Task<UserInfo> FindUserDetailsByEmailAsync(string email, CancellationToken cancellationToken = default)
        {
            var normalizedEmail = NormalizeEmail(email);

            var userDetailsQuery =
                from user in _userManager.Users.AsNoTracking()
                where user.NormalizedEmail == normalizedEmail
                select new UserInfo
                {
                    User = user,
                    Roles = user.UserRoles
                        .Join(_roleManager.Roles.AsNoTracking(),
                              ur => ur.RoleId,
                              r => r.Id,
                              (ur, r) => r.Name!)
                        .ToList(),
                    // Menor Level == role mais poderosa; se não tiver roles, assume int.MaxValue (mais fraco)
                    TopRoleLevel = user.UserRoles
                        .Join(_roleManager.Roles.AsNoTracking(),
                              ur => ur.RoleId,
                              r => r.Id,
                              (ur, r) => r.Level)
                        .DefaultIfEmpty(int.MaxValue)
                        .Min()
                };

            var userDetails = await userDetailsQuery.FirstOrDefaultAsync(cancellationToken);

            if (userDetails == null)
                throw new NotFoundException("Usuário não encontrado.");

            return userDetails;
        }

        private async Task<ApplicationRole> FindRoleByNameAsync(string roleName)
        {
            var normalizedRoleName = NormalizeRoleName(roleName);
            var role = await _roleManager.FindByNameAsync(normalizedRoleName);
            if (role == null)
                throw new NotFoundException($"Role '{normalizedRoleName}' não encontrada.");
            return role;
        }

        private static string GetErrors(IdentityResult result)
        {
            return string.Join("; ", result.Errors.Select(e => e.Description));
        }
    }
}