using System.Security.Claims;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class LoggedUserInfo
    {
        public string Email { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public IList<string> Roles { get; set; } = new List<string>();
        public IList<Claim> Claims { get; set; } = new List<Claim>();
        public int? TopRoleLevel { get; set; } = 999;
    }
}
