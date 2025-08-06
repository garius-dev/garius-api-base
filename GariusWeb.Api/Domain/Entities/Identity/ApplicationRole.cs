using Microsoft.AspNetCore.Identity;

namespace GariusWeb.Api.Domain.Entities.Identity
{
    public class ApplicationRole : IdentityRole<Guid>
    {
        public ApplicationRole() : base() { }
        public ApplicationRole(string roleName) : base(roleName) { }

        public ApplicationRole(string roleName, string? description, int level) : base(roleName)
        {
            Description = description;
            Level = level;
        }

        public string? Description { get; set; }
        public int Level { get; set; }
    }
}
