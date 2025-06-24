using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Web;
using static GariusWeb.Api.Configuration.AppSecrets;

namespace GariusWeb.Api.Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly JwtSettings _jwtSettings;

        public AuthService(UserManager<ApplicationUser> userManager,
                       IEmailSender emailSender,
                       IOptions<JwtSettings> jwtSettings)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _jwtSettings = jwtSettings.Value;
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
                IsExternalLogin = false
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

            if (!await _userManager.CheckPasswordAsync(user, request.Password))
            {
                await _userManager.AccessFailedAsync(user);
                throw new UnauthorizedAccessAppException("Senha inválida.");
            }

            await _userManager.ResetAccessFailedCountAsync(user);

            // Em breve: gerar JWT aqui
            return "JWT-TOKEN-AQUI";
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

    }
}
