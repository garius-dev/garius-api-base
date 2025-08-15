using GariusWeb.Api.Domain.Entities.Identity;

namespace GariusWeb.Api.Application.Dtos.UserAndRoles
{
    public class UserDetailsDto
    {
        public ApplicationUser User { get; set; } = default!;
        public IList<string> Roles { get; set; } = new List<string>();
        public int TopRoleLevel { get; set; } = int.MaxValue;
    }
}
