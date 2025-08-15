using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Domain.Entities.Identity
{
    public class ApplicationRole : IdentityRole<Guid>
    {
        public ApplicationRole() : base()
        {
        }

        public ApplicationRole(string roleName) : base(roleName)
        {
        }

        public ApplicationRole(string roleName, string? description, int level) : base(roleName)
        {
            Description = description;
            Level = level;
        }

        [MaxLength(250, ErrorMessage = "A 'Descrição' deve ter no máximo 250 caracteres.")]
        public string? Description { get; set; }

        public int Level { get; set; }

        public virtual ICollection<IdentityUserRole<Guid>> UserRoles { get; set; } = new List<IdentityUserRole<Guid>>();
    }
}