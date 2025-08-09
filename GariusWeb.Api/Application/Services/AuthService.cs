using AngleSharp.Css;
using GariusWeb.Api.Application.Dtos;
using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Helpers;
using GariusWeb.Api.Infrastructure.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Data;
using System.Security.Claims;
using System.Web;
using static GariusWeb.Api.Configuration.AppSecrets;

namespace GariusWeb.Api.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly JwtSettings _jwtSettings;
        private readonly IJwtTokenGenerator _jwtTokenGenerator;
        private readonly LoggedUserHelper _loggedUserHelper;

        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthService(UserManager<ApplicationUser> userManager,
                       IEmailSender emailSender,
                       IOptions<JwtSettings> jwtSettings,
                       IJwtTokenGenerator jwtTokenGenerator,
                       SignInManager<ApplicationUser> signInManager,
                       IHttpContextAccessor httpContextAccessor,
                       RoleManager<ApplicationRole> roleManager,
                       LoggedUserHelper loggedUserHelper)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _jwtSettings = jwtSettings.Value;
            _jwtTokenGenerator = jwtTokenGenerator;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _roleManager = roleManager;
            _loggedUserHelper = loggedUserHelper;
        }

        public async Task<List<string>> GetRolesAsync()
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();

            var roles = await _roleManager.Roles
                .Where(r => r.Level >= loggedUserInfo.TopRoleLevel)
                .Select(s => s.Name)
                .Where(name => !string.IsNullOrEmpty(name))
                .Select(name => name!)
                .ToListAsync();

            return roles;
        }

        public async Task<PagedResult<UserRoleResponse>> GetUsersWithRolesAsync(string? search, int page = 1, int pageSize = 20)
        {
            var query = _userManager.Users.AsQueryable();

            // Filtro de busca
            if (!string.IsNullOrWhiteSpace(search))
            {
                search = search.ToLower();
                query = query.Where(u =>
                    u.UserName!.ToLower().Contains(search) ||
                    u.Email!.ToLower().Contains(search));
            }

            var totalCount = await query.CountAsync();

            // Paginação
            var users = await query
                .OrderBy(u => u.UserName)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            // Montar DTO com roles
            var userDtos = new List<UserRoleResponse>();
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                string userName = user.FirstName + " " + user.LastName;
                
                userDtos.Add(new UserRoleResponse
                {
                    Id = user.Id,
                    Email = user.Email ?? "unknow",
                    UserName = userName ?? "unknow",
                    Roles = roles.ToList()
                });
            }

            return new PagedResult<UserRoleResponse>
            {
                TotalCount = totalCount,
                Items = userDtos
            };
        }


        public async Task<bool> CreateRoleIfNotExistsAsync(CreateRoleRequest request)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();

            if (loggedUserInfo.TopRoleLevel > request.RoleLevel)
                throw new UnauthorizedAccessAppException($"Você não tem permissão para criar a role '{request.RoleName}'.");

            if (string.IsNullOrWhiteSpace(request.RoleName))
                throw new BadRequestException("O nome da role não pode ser vazio.");

            var roleExists = await _roleManager.RoleExistsAsync(request.RoleName);

            if (!roleExists)
            {
                var result = await _roleManager.CreateAsync(new ApplicationRole(request.RoleName, null, request.RoleLevel));


                if (!result.Succeeded)
                {
                    throw new InternalServerErrorAppException("Erro ao criar role: " + string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }

            return true;
        }

        public async Task<bool> AddRoleToUserAsync(string userEmail, string roleName)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();

            var user = await _userManager.FindByEmailAsync(userEmail)
                ?? throw new NotFoundException("Usuário não encontrado.");

            var userRoles = await _userManager.GetRolesAsync(user);
            if (userRoles != null && userRoles.Any())
                throw new ConflictException("Usuário já possui uma role.");

            var role = await _roleManager.Roles.Where(r => r.Name == roleName).FirstOrDefaultAsync();
            if (role == null)
                throw new NotFoundException($"Role '{roleName}' não existe.");

            if (loggedUserInfo.TopRoleLevel > role.Level)
                throw new UnauthorizedAccessAppException($"Você não tem permissão para adicionar a role '{roleName}' ao usuário selecionado.");

            var result = await _userManager.AddToRoleAsync(user, roleName);
            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao adicionar Role: " +
                    string.Join(", ", result.Errors.Select(e => e.Description)));

            return true;
        }

        public async Task<List<string>> GetUserRoles(string userEmail)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();

            var user = await _userManager.FindByEmailAsync(userEmail)
                ?? throw new NotFoundException("Usuário não encontrado.");

            var userRoles = await _userManager.GetRolesAsync(user);

            if (userRoles.Count == 0)
                return new List<string>();

            var targetTopRoleLevel = await _roleManager.Roles
                .Where(r => userRoles.Contains(r.Name!))
                .OrderBy(r => r.Level)
                .Select(r => r.Level)
                .FirstOrDefaultAsync();

            if (loggedUserInfo.TopRoleLevel > targetTopRoleLevel)
                throw new UnauthorizedAccessAppException(
                    "Você não tem permissão para ler as roles deste usuário."
                );

            return userRoles.ToList();
        }

        public async Task<bool> RemoveRoleFromUserAsync(string userEmail, string roleName)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();

            var user = await _userManager.FindByEmailAsync(userEmail)
                ?? throw new NotFoundException("Usuário não encontrado.");


            // Pega o top role level do usuário alvo
            var userRoles = await _userManager.GetRolesAsync(user);

            if (userRoles.Count == 0)
                throw new OperationNotAllowedException("Usuário não possui nenhuma role vinculada.");

            var targetTopRoleLevel = await _roleManager.Roles
                .Where(r => userRoles.Contains(r.Name!))
                .OrderBy(r => r.Level)
                .Select(r => r.Level)
                .FirstOrDefaultAsync();

            // Não permitir remover role de alguém com nível igual ou superior
            if (loggedUserInfo.TopRoleLevel >= targetTopRoleLevel)
                throw new UnauthorizedAccessAppException(
                    "Você não tem permissão para remover roles deste usuário."
                );

            if(roleName == "all")
            {
                if (userRoles == null || userRoles.Count == 0)
                    return true;
                                
                var resultAll = await _userManager.RemoveFromRolesAsync(user, userRoles);
                if (!resultAll.Succeeded)
                    throw new InternalServerErrorAppException("Erro ao remover as Roles: " +
                        string.Join(", ", resultAll.Errors.Select(e => e.Description)));

                return true;
            }

            var role = await _roleManager.Roles
                .Where(r => r.Name == roleName)
                .FirstOrDefaultAsync();

            if (role == null)
                throw new NotFoundException($"Role '{roleName}' não existe.");

            if (!userRoles.Contains(roleName))
                throw new ConflictException("Usuário não possui esta role.");


            var result = await _userManager.RemoveFromRoleAsync(user, roleName);
            if (!result.Succeeded)
                throw new InternalServerErrorAppException("Erro ao remover Role: " +
                    string.Join(", ", result.Errors.Select(e => e.Description)));

            return true;
        }

        public async Task<bool> UpdateUserRoleAsync(string userEmail, string newRoleName)
        {
            var loggedUserInfo = await _loggedUserHelper.GetLoggedUserInfoAsync();

            var user = await _userManager.FindByEmailAsync(userEmail)
                ?? throw new NotFoundException("Usuário não encontrado.");

            // Pega role atual do usuário (deve ser apenas uma)
            var currentRoles = await _userManager.GetRolesAsync(user);
            if (currentRoles.Count > 1)
                throw new ConflictException("Usuário possui mais de uma role, o que não deveria acontecer.");

            if(currentRoles.Count == 0)
                throw new OperationNotAllowedException("Usuário não possui nenhuma role vinculada.");

            var currentRoleName = currentRoles.FirstOrDefault();

            // Obtém nível hierárquico do usuário alvo
            var targetTopRoleLevel = await _roleManager.Roles
                .Where(r => currentRoles.Contains(r.Name!))
                .OrderBy(r => r.Level)
                .Select(r => r.Level)
                .FirstOrDefaultAsync();

            // Bloqueia alteração se usuário logado não for hierarquicamente superior
            if (loggedUserInfo.TopRoleLevel >= targetTopRoleLevel)
                throw new UnauthorizedAccessAppException(
                    "Você não tem permissão para alterar a role deste usuário."
                );

            // Busca a nova role
            var newRole = await _roleManager.Roles
                .Where(r => r.Name == newRoleName)
                .FirstOrDefaultAsync();

            if (newRole == null)
                throw new NotFoundException($"Role '{newRoleName}' não existe.");

            // Não permitir trocar para a mesma role
            if (string.Equals(currentRoleName, newRoleName, StringComparison.OrdinalIgnoreCase))
                throw new ConflictException("Usuário já possui esta role.");

            // Remove role atual (se existir)
            if (!string.IsNullOrEmpty(currentRoleName))
            {
                var removeResult = await _userManager.RemoveFromRoleAsync(user, currentRoleName);
                if (!removeResult.Succeeded)
                    throw new InternalServerErrorAppException("Erro ao remover Role atual: " +
                        string.Join(", ", removeResult.Errors.Select(e => e.Description)));
            }

            // Adiciona nova role
            var addResult = await _userManager.AddToRoleAsync(user, newRoleName);
            if (!addResult.Succeeded)
                throw new InternalServerErrorAppException("Erro ao adicionar nova Role: " +
                    string.Join(", ", addResult.Errors.Select(e => e.Description)));

            return true;
        }

        public async Task RegisterAsync(RegisterRequest request)
        {
            var existing = await _userManager.FindByEmailAsync(request.Email);
            if (existing != null)
                throw new ConflictException("Email já está em uso.");


            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName.SanitizeInput(),
                LastName = request.LastName.SanitizeInput(),
                IsExternalLogin = false,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
                throw new ValidationException(string.Join("; ", result.Errors.Select(e => e.Description)));

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = HttpUtility.UrlEncode(token);

            var confirmLink = $"{_jwtSettings.EmailConfirmationUrl}?userId={user.Id}&token={encodedToken}";

            var body = $"<h3>Confirme seu e-mail</h3><p><a href='{confirmLink}'>Clique aqui para confirmar</a></p>";
            await _emailSender.SendEmailAsync(user.Email!, "Confirmação de e-mail", body);
        }

        public async Task<string> LoginAsync(LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email)
                       ?? throw new NotFoundException("Usuário");

            if (!user.IsActive)
                throw new ForbiddenAccessException("Usuário inativo.");

            if (!await _userManager.IsEmailConfirmedAsync(user))
                throw new ForbiddenAccessException("Email ainda não confirmado.");

            if (user.IsExternalLogin)
                throw new ForbiddenAccessException($"Este e-mail está vinculado a um login externo.\r\n\r\nPara acessar sua conta, continue com o provedor utilizado no cadastro: {user.ExternalProvider}.");

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

            if (!result.Succeeded)
            {
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");
            }

            await _userManager.ResetAccessFailedCountAsync(user);

            // Obter as roles do usuário
            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);

            // Em breve: gerar JWT aqui
            return _jwtTokenGenerator.GenerateToken(user, roles, claims);
        }

        public ChallengeResult GetExternalLoginChallangeAsync(string provider, string redirectUrl)
        {
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            return new ChallengeResult(provider, properties);
        }

        public async Task<string> ExternalLoginCallbackAsync(string transitionUrl, string? returnUrl)
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();

            if (info == null)
                throw new ValidationException("Não foi possível obter informações do provedor externo.");

            var email = info.Principal.FindFirstValue(ClaimTypes.Email);

            if (string.IsNullOrEmpty(email))
                throw new ValidationException("E-mail não fornecido pelo provedor externo.");

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                user = new ApplicationUser
                {
                    FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName) ?? "Usuário",
                    LastName = info.Principal.FindFirstValue(ClaimTypes.Surname) ?? "Externo",
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true,
                    IsExternalLogin = true,
                    ExternalProvider = info.LoginProvider,
                    CreatedAt = DateTime.UtcNow
                };

                var result = await _userManager.CreateAsync(user);

                if (!result.Succeeded)
                    throw new ValidationException("Erro ao criar usuário externo.");
            }

            if (!user.EmailConfirmed)
                throw new UnauthorizedAccessException("E-mail não confirmado.");

            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);

            var token = _jwtTokenGenerator.GenerateToken(user, roles.ToList(), claims);

            var query = new Dictionary<string, string?>
            {
                ["token"] = token
            };

            if (!string.IsNullOrWhiteSpace(returnUrl))
                query["returnUrl"] = returnUrl;

            return QueryHelpers.AddQueryString(transitionUrl, query);
        }

        public async Task ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId)
                       ?? throw new NotFoundException("Usuário");

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (!result.Succeeded)
                throw new ValidationException("Não foi possível confirmar o e-mail.");
        }

        public async Task ForgotPasswordAsync(ForgotPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                return; // Silencia para evitar enumeração de e-mails

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = HttpUtility.UrlEncode(token);

            var callbackUrl = $"{_jwtSettings.PasswordResetUrl}?email={HttpUtility.UrlEncode(request.Email)}&token={encodedToken}";
            var body = $"<p>Para redefinir sua senha, <a href='{callbackUrl}'>clique aqui</a>.</p>";

            await _emailSender.SendEmailAsync(request.Email, "Redefinir senha", body);
        }

        public async Task ResetPasswordAsync(ResetPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email)
                       ?? throw new NotFoundException("Usuário");

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);

            if (!result.Succeeded)
                throw new ValidationException("Não foi possível redefinir a senha: " +
                    string.Join("; ", result.Errors.Select(e => e.Description)));
        }

        public string GetExternalLoginUrl(string provider, string redirectUrl)
        {
            var httpContext = _httpContextAccessor.HttpContext!;
            return ExternalAuthUrlHelper.GetExternalAuthenticationUrl(httpContext, provider, redirectUrl);
        }
    }
}
