using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Helpers;
using GariusWeb.Api.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Web;
using static GariusWeb.Api.Configuration.AppSecrets;

namespace GariusWeb.Api.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly JwtSettings _jwtSettings;
        private readonly IJwtTokenGenerator _jwtTokenGenerator;

        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthService(UserManager<ApplicationUser> userManager,
                       IEmailSender emailSender,
                       IOptions<JwtSettings> jwtSettings,
                       IJwtTokenGenerator jwtTokenGenerator,
                       SignInManager<ApplicationUser> signInManager,
                       IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _jwtSettings = jwtSettings.Value;
            _jwtTokenGenerator = jwtTokenGenerator;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
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
                FirstName = request.FirstName,
                LastName = request.LastName,
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
                throw new UnauthorizedAccessAppException("Email ainda não confirmado.");

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

            if (!result.Succeeded)
            {
                throw new UnauthorizedAccessException("Credenciais inválidas.");
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
