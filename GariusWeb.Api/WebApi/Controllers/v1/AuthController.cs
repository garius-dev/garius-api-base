using Asp.Versioning;
using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Entities.Identity;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace GariusWeb.Api.WebApi.Controllers.v1
{
    [ApiController]
    [Route("api/v{version:apiVersion}/auth")]
    [ApiVersion("1.0")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthController(IAuthService authService, SignInManager<ApplicationUser> signInManager)
        {
            _authService = authService;
            _signInManager = signInManager;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                throw new Application.Exceptions.ValidationException("Requisição inválida");

            await _authService.RegisterAsync(request);
            return Ok(ApiResponse<string>.Ok("Usuário registrado com sucesso. Verifique seu e-mail."));
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                throw new Application.Exceptions.ValidationException("Requisição inválida");

            var token = await _authService.LoginAsync(request);
            return Ok(ApiResponse<string>.Ok(token, "Login realizado com sucesso"));
        }

        [HttpGet("external-login/{provider}")]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, [FromQuery] string transitionUrl, [FromQuery] string returnUrl = "/")
        {
            if (string.IsNullOrWhiteSpace(transitionUrl))
                return BadRequest("transitionUrl é obrigatório e deve ser válido.");


            var redirectUrl = Url.Action(nameof(ExternalCallback), "Auth", new { returnUrl, transitionUrl }, protocol: Request.Scheme);
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            return new ChallengeResult(provider, properties);
        }

        [HttpGet("external-login-callback")]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalCallback([FromQuery] string transitionUrl, [FromQuery] string returnUrl = "/")
        {
            if (string.IsNullOrWhiteSpace(transitionUrl))
                return BadRequest("transitionUrl é obrigatório e deve ser válido.");

            var token = await _authService.ExternalLoginCallbackAsync();

            var query = new Dictionary<string, string?>
            {
                ["token"] = token
            };

            if (!string.IsNullOrWhiteSpace(returnUrl))
                query["returnUrl"] = returnUrl;

            var redirectUrl = QueryHelpers.AddQueryString(transitionUrl, query);

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
                throw new Application.Exceptions.ValidationException("Requisição inválida");

            await _authService.ForgotPasswordAsync(request);
            return Ok(ApiResponse<string>.Ok("Se o e-mail estiver correto, instruções foram enviadas"));
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            if (!ModelState.IsValid)
                throw new Application.Exceptions.ValidationException("Requisição inválida");

            await _authService.ResetPasswordAsync(request);
            return Ok(ApiResponse<string>.Ok("Senha redefinida com sucesso"));
        }
    }
}
