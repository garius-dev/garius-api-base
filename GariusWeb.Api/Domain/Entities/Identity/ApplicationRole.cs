using Microsoft.AspNetCore.Identity;

namespace GariusWeb.Api.Domain.Entities.Identity
{
    public class ApplicationRole : IdentityRole<Guid>
    {
        public ApplicationRole() : base() { }
        public ApplicationRole(string roleName) : base(roleName) { }

        public string? Description { get; set; }
    }
}
