using GariusWeb.Api.Domain.Entities.Identity;

namespace GariusWeb.Api.Application.Interfaces
{
    public interface IJwtTokenGenerator
    {
        string GenerateToken(ApplicationUser user, IList<string> roles);
    }
}
