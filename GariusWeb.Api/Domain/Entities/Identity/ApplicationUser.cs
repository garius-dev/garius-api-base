using Microsoft.AspNetCore.Identity;

namespace GariusWeb.Api.Domain.Entities.Identity
{
    public class ApplicationUser : IdentityUser<Guid>
    {
        public string FirstName { get; set; } = default!;
        public string LastName { get; set; } = default!;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }

        public bool IsExternalLogin { get; set; }
        public bool IsActive { get; set; }
        public string? ExternalProvider { get; set; } // Google, Microsoft

        public Guid? TenantId { get; set; } // futuro suporte a SaaS
    }
}
