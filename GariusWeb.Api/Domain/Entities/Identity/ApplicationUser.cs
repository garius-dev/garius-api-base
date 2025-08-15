using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Domain.Entities.Identity
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        [Required(ErrorMessage = "O 'Nome' é obrigatório.")]
        [MaxLength(100, ErrorMessage = "O 'Nome' deve ter no máximo 100 caracteres.")]
        public string FirstName { get; set; } = default!;

        [Required(ErrorMessage = "O 'Sobrenome' é obrigatório.")]
        [MaxLength(100, ErrorMessage = "O 'Sobrenome' deve ter no máximo 100 caracteres.")]
        public string LastName { get; set; } = default!;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public bool IsExternalLogin { get; set; }
        public bool IsActive { get; set; } = true;
        public string? ExternalProvider { get; set; } // Google, Microsoft
        public Guid? TenantId { get; set; } // futuro suporte a SaaS
        public virtual ICollection<IdentityUserRole<Guid>> UserRoles { get; set; } = new List<IdentityUserRole<Guid>>();
    }
}