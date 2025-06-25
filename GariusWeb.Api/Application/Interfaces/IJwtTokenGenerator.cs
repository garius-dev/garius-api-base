using GariusWeb.Api.Domain.Entities.Identity;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IJwtTokenGenerator
    {
        string GenerateToken(ApplicationUser user, IList<string> roles, IList<Claim>? additionalClaims = null);
    }
}
