using GariusWeb.Api.Domain.Entities.Identity;

namespace GariusWeb.Api.Application.Dtos.UserAndRoles
{
    public class UserDetailsDto
    {
        public string Id { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public IList<string> Roles { get; set; } = new List<string>();
    }
}