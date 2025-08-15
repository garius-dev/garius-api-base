using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Domain.Interfaces;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using System.Data;
using System.Security.Claims;
using System.Security.Cryptography;
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
        private readonly ICacheService _cacheService;

        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthService(UserManager<ApplicationUser> userManager,
                       IEmailSender emailSender,
                       IOptions<JwtSettings> jwtSettings,
                       IJwtTokenGenerator jwtTokenGenerator,
                       SignInManager<ApplicationUser> signInManager,
                       IHttpContextAccessor httpContextAccessor,
                       ICacheService cacheService)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _jwtSettings = jwtSettings.Value;
            _jwtTokenGenerator = jwtTokenGenerator;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _cacheService = cacheService;
        }

        private class LoginPayload
        {
            public Guid UserId { get; set; }
            public IList<string> Roles { get; set; } = new List<string>();
            public IList<Claim> Claims { get; set; } = new List<Claim>();
        }

        private string GetApiBaseUrl(string segment)
        {
            var ctx = _httpContextAccessor.HttpContext
                      ?? throw new InvalidOperationException("HttpContext Error: Chamada Inválida");

            var baseUrl = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
            var version = ctx.GetRequestedApiVersion()?.MajorVersion
                          ?? throw new InvalidOperationException("HttpContext Error: Versão Inválida");

            return $"{baseUrl}/api/v{version}/{segment}";
        }

        private async Task EnsureUserCanLoginAsync(ApplicationUser? user, bool isExternalLogin = false)
        {
            if (user == null)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200));
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");
            }

            bool isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);

            if (!user.IsActive || !isEmailConfirmed)
            {
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");
            }

            // Para login interno, o usuário não pode ser um usuário de login externo.
            // Para login externo, o usuário DEVE ser um usuário de login externo.
            if (isExternalLogin != user.IsExternalLogin)
            {
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");
            }
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

            user.Fullname = $"{user.FirstName} {user.LastName}".Trim();
            user.NormalizedFullName = user.Fullname.ToUpperInvariant();

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
                throw new ValidationException(string.Join("; ", result.Errors.Select(e => e.Description)));

            // Token de confirmação de e-mail em Base64Url
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(token));

            ///api/v1/auth/confirm-email
            var confirmEmailEndpoint = GetApiBaseUrl(_jwtSettings.EmailConfirmationUrl);
            var confirmLink = $"{confirmEmailEndpoint}?userId={user.Id}&token={encodedToken}";

            var body = $"<h3>Confirme seu e-mail</h3><p><a href='{confirmLink}'>Clique aqui para confirmar</a></p>";
            await _emailSender.SendEmailAsync(user.Email!, "Confirmação de e-mail", body);
        }

        public async Task<string> LoginAsync(LoginRequest request)
        {
            // Busca do usuário
            var user = await _userManager.FindByEmailAsync(request.Email);

            await EnsureUserCanLoginAsync(user, isExternalLogin: false);

            // Verificação de credenciais com lockout habilitado
            var result = await _signInManager.CheckPasswordSignInAsync(user!, request.Password, lockoutOnFailure: true);

            if (!result.Succeeded)
                throw new UnauthorizedAccessAppException("Credenciais inválidas.");

            // Sucesso: zera o contador de falhas e gera o token
            await _userManager.ResetAccessFailedCountAsync(user!);

            var roles = await _userManager.GetRolesAsync(user!);
            var claims = await _userManager.GetClaimsAsync(user!);

            return _jwtTokenGenerator.GenerateToken(user!, roles, claims);
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

                user.Fullname = $"{user.FirstName} {user.LastName}".Trim();
                user.NormalizedFullName = user.Fullname.ToUpperInvariant();

                var result = await _userManager.CreateAsync(user);

                if (!result.Succeeded)
                    throw new ValidationException("Erro ao criar usuário externo.");
            }

            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);

            var code = TextExtensions.CreateOneTimeCode();
            var codeBytes = WebEncoders.Base64UrlDecode(code);
            var codeHash = Convert.ToHexString(SHA256.HashData(codeBytes));

            await _cacheService.SetAsync(
                $"ext_code:{codeHash}",
                new LoginPayload { UserId = user.Id, Roles = roles, Claims = claims },
                TimeSpan.FromMinutes(1));

            var parts = new List<string> { $"code={Uri.EscapeDataString(code)}" };
            if (!string.IsNullOrWhiteSpace(returnUrl))
                parts.Add($"returnUrl={Uri.EscapeDataString(returnUrl)}");

            return $"{transitionUrl}#{string.Join("&", parts)}";
        }

        public async Task<string> ExchangeCode(string code)
        {
            if (!TextExtensions.TryGetCodeHash(code, out var codeHash))
                throw new BadRequestException("Código inválido ou expirado.");

            string cacheKey = $"ext_code:{codeHash}";

            var payload = await _cacheService.GetAsync<LoginPayload>(cacheKey);

            if (payload == null)
                throw new BadRequestException("Código inválido ou expirado.");

            await _cacheService.RemoveAsync(cacheKey);

            var user = await _userManager.FindByIdAsync(payload.UserId.ToString());

            await EnsureUserCanLoginAsync(user, isExternalLogin: true);

            var token = _jwtTokenGenerator.GenerateToken(user!, payload.Roles, payload.Claims);
            return token;
        }

        public async Task ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new BadRequestException("Link inválido ou expirado.");

            string decodedToken;
            try
            {
                var tokenBytes = WebEncoders.Base64UrlDecode(token);
                decodedToken = System.Text.Encoding.UTF8.GetString(tokenBytes);
            }
            catch
            {
                throw new BadRequestException("Link inválido ou expirado.");
            }

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);

            if (!result.Succeeded)
                throw new BadRequestException("Link inválido ou expirado.");
        }

        public async Task ForgotPasswordAsync(ForgotPasswordRequest request)
        {
            // Se existir e estiver confirmado, envia o e-mail; caso contrário, responde normalmente (silencioso).
            var user = await _userManager.FindByEmailAsync(request.Email);

            if (user != null && await _userManager.IsEmailConfirmedAsync(user))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                //var encodedToken = HttpUtility.UrlEncode(token);

                // Token de reset em Base64Url
                var encodedToken = WebEncoders.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(token));

                var resetLink = $"{_jwtSettings.PasswordResetUrl}?email={Uri.EscapeDataString(user.Email!)}&token={encodedToken}";
                var body = $"<h3>Redefinir senha</h3><p><a href='{resetLink}'>Clique aqui para redefinir sua senha</a></p>";

                // Em caso de erro de envio, logar internamente via middleware/observabilidade
                try
                {
                    await _emailSender.SendEmailAsync(user.Email!, "Redefinição de senha", body);
                }
                catch
                {
                    // logar internamente; não propagar erro
                }
            }
        }

        public async Task ResetPasswordAsync(ResetPasswordRequest request)
        {
            // Não revelar se o e-mail é válido; aplicar fluxo neutro
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                // Mitigar timing
                await Task.Delay(TimeSpan.FromMilliseconds(100));
                return;
            }

            // Decodifica o token Base64Url recebido
            string decodedToken;
            try
            {
                var tokenBytes = WebEncoders.Base64UrlDecode(request.Token);
                decodedToken = System.Text.Encoding.UTF8.GetString(tokenBytes);
            }
            catch
            {
                throw new BadRequestException("Não foi possível redefinir a senha. Link inválido ou expirado.");
            }

            var result = await _userManager.ResetPasswordAsync(user, decodedToken, request.NewPassword);

            if (!result.Succeeded)
                throw new BadRequestException("Não foi possível redefinir a senha. Link inválido ou expirado.");
        }

        public string GetExternalLoginUrl(string provider, string redirectUrl)
        {
            var httpContext = _httpContextAccessor.HttpContext!;
            return ExternalAuthUrlHelper.GetExternalAuthenticationUrl(httpContext, provider, redirectUrl);
        }
    }
}