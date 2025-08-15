using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Domain.Entities.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace GariusWeb.Api.Helpers
{
    public class LoggedUserHelper
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public LoggedUserHelper(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<LoggedUserInfo> GetLoggedUserInfoAsync()
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null || httpContext.User == null)
                throw new UnauthorizedAccessAppException("Usuário não autenticado.");

            var userPrincipal = httpContext?.User;
            if (userPrincipal == null || userPrincipal.Identity == null || !userPrincipal.Identity.IsAuthenticated)
                throw new UnauthorizedAccessAppException("Usuário não autenticado.");

            var email = userPrincipal.FindFirstValue(ClaimTypes.Email);
            var name = userPrincipal.Identity?.Name ?? email ?? "";

            if (string.IsNullOrEmpty(email))
                throw new UnauthorizedAccessAppException("Não foi possível obter o e-mail do usuário logado.");

            var appUser = await _userManager.FindByEmailAsync(email);
            if (appUser == null)
                throw new NotFoundException("Usuário logado não encontrado.");

            var roles = await _userManager.GetRolesAsync(appUser);
            var claims = await _userManager.GetClaimsAsync(appUser);

            int topRoleLevel = 999;
            if (_roleManager.Roles != null && _roleManager.Roles.Any() && roles != null && roles.Any())
            {
                var roleObjs = _roleManager.Roles.Where(r => roles.Contains(r.Name ?? "unknow"));
                if (roleObjs != null && roleObjs.Any())
                {
                    topRoleLevel = await roleObjs.MinAsync(r => (int?)r.Level) ?? 999;
                }
            }

            return new LoggedUserInfo
            {
                UserId = appUser.Id,
                Email = email,
                Name = name,
                Roles = roles ?? new List<string>(),
                Claims = claims,
                TopRoleLevel = topRoleLevel
            };
        }
    }
}