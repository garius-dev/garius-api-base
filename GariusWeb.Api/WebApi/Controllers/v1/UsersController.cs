using Asp.Versioning;
using GariusWeb.Api.Application.Dtos.Auth;
using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using GariusWeb.Api.Domain.Abstractions;
using GariusWeb.Api.Extensions;
using GariusWeb.Api.Helpers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GariusWeb.Api.WebApi.Controllers.v1
{
    [ApiController]
    [Route("api/v{version:apiVersion}/users")]
    [ApiVersion("1.0")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly IRoleService _roleService;

        public UsersController(IUserService userService, IRoleService roleService)
        {
            _userService = userService;
            _roleService = roleService;
        }

        [Authorize]
        [HttpGet("get-users")]
        public async Task<IActionResult> GetUsers(
            [FromQuery] int pageSize = 10,
            [FromQuery] string? lastId = null,
            [FromQuery] string? searchTerm = null,
            CancellationToken cancellationToken = default)
        {
            if (pageSize <= 0)
            {
                throw new BadRequestException("'page size' deve ser maior que zero.");
            }

            var result = await _userService.GetUsersPagedAsync(pageSize, lastId, searchTerm, cancellationToken);

            return Ok(ApiResponse<PagedResult<Application.Dtos.UserAndRoles.UserDetailsDto>>.Ok(result));
        }

        [Authorize]
        [HttpGet("get-roles")]
        public async Task<IActionResult> GetRoles(CancellationToken cancellationToken = default)
        {
            List<string> roles = await _roleService.GetRolesAsync(cancellationToken);

            return Ok(ApiResponse<List<string>>.Ok(roles));
        }

        [Authorize]
        [HttpPost("add-role")]
        public async Task<IActionResult> AddRole([FromBody] CreateRoleRequest request)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida: " + ModelState.ToFormattedErrorString());

            await _roleService.CreateRoleAsync(request);

            return Ok(ApiResponse<string>.Ok($"Role '{request.RoleName}' criada com sucesso"));
        }

        [Authorize]
        [HttpPost("add-role-to-user")]
        public async Task<IActionResult> AddRoleToUser([FromBody] UserRoleRequest request, CancellationToken cancellationToken = default)
        {
            if (!ModelState.IsValid)
                throw new ValidationException("Requisição inválida: " + ModelState.ToFormattedErrorString());

            await _roleService.AddRoleToUserAsync(request, cancellationToken);
            return Ok(ApiResponse<string>.Ok($"Role '{request.RoleName}' vinculada ao usuário '{request.Email}' com sucesso"));
        }
    }
}