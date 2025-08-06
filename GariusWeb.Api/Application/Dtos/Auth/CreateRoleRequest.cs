using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Application.Dtos.Auth
{
    public class CreateRoleRequest
    {
        [Required(ErrorMessage = "O nome da role é obrigatório.")]
        [MaxLength(50, ErrorMessage = "O nome da role deve ter no máximo 50 caracteres.")]
        [MinLength(3, ErrorMessage = "O nome da role deve ter no mínimo 3 caracteres.")]
        public string RoleName { get; set; } = string.Empty;

        [Range(0, 999, ErrorMessage = "O nível deve estar entre 0 e 999.")]
        public int RoleLevel { get; set; } = 999;
    }
}
