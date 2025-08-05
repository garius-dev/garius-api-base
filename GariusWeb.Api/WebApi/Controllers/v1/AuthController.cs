using Asp.Versioning;
using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace GariusWeb.Api.WebApi.Controllers.v1
{
    [ApiController]
    [Route("api/v{version:apiVersion}/auth")]
    [ApiVersion("1.0")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        [EnableRateLimiting("RegisterPolicy")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida");

            await _authService.RegisterAsync(request);
            return Ok(ApiResponse<string>.Ok("Usuário registrado com sucesso. Verifique seu e-mail."));
        }

        [HttpPost("login")]
        [EnableRateLimiting("LoginPolicy")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida");

            var token = await _authService.LoginAsync(request);

            return Ok(ApiResponse<string>.Ok(token, "Login realizado com sucesso"));
        }

        [HttpGet("external-login/{provider}")]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, [FromQuery] string transitionUrl, [FromQuery] string returnUrl = "/")
        {
            if (string.IsNullOrWhiteSpace(transitionUrl))
                throw new ValidationException("transitionUrl é obrigatório e deve ser válido.");

            var redirectUrl = Url.Action(nameof(ExternalCallback), "Auth", new { returnUrl, transitionUrl }, protocol: Request.Scheme);

            if (string.IsNullOrWhiteSpace(redirectUrl))
                throw new ValidationException("redirectUrl é obrigatóri'o' e deve ser válido.");

            return _authService.GetExternalLoginChallangeAsync(provider, redirectUrl);
        }

        [HttpGet("external-login/{provider}/url")]
        [AllowAnonymous]
        public IActionResult GetExternalLoginUrl(string provider, [FromQuery] string transitionUrl, [FromQuery] string returnUrl = "/")
        {
            if (string.IsNullOrWhiteSpace(transitionUrl))
                throw new ValidationException("transitionUrl é obrigatório e deve ser válido.");

            var redirectUrl = Url.Action(nameof(ExternalCallback), "Auth", new { returnUrl, transitionUrl }, protocol: Request.Scheme);

            if (string.IsNullOrWhiteSpace(redirectUrl))
                throw new ValidationException("redirectUrl é obrigatório e deve ser válido.");

            var loginUrl = _authService.GetExternalLoginUrl(provider, redirectUrl);

            return Ok(ApiResponse<string>.Ok(loginUrl));
        }

        [HttpGet("external-login-callback")]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalCallback([FromQuery] string transitionUrl, [FromQuery] string returnUrl = "/")
        {
            if (string.IsNullOrWhiteSpace(transitionUrl))
                throw new ValidationException("transitionUrl é obrigatório e deve ser válido.");

            var redirectUrl = await _authService.ExternalLoginCallbackAsync(transitionUrl, returnUrl);

            return Redirect(redirectUrl);
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
        {
            await _authService.ConfirmEmailAsync(userId, token);

            return Ok(ApiResponse<string>.Ok("E-mail confirmado com sucesso"));
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida");

            await _authService.ForgotPasswordAsync(request);

            return Ok(ApiResponse<string>.Ok("Se o e-mail estiver correto, instruções foram enviadas"));
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida");

            await _authService.ResetPasswordAsync(request);

            return Ok(ApiResponse<string>.Ok("Senha redefinida com sucesso"));
        }
    }
}