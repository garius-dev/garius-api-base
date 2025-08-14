using GariusWeb.Api.Domain.Entities.Identity;
using System.Security.Claims;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class LoginPayload
    {
        public ApplicationUser User { get; set; }
        public IList<string> Roles { get; set; } = new List<string>();
        public IList<Claim> Claims { get; set; } = new List<Claim>();
    }
}
