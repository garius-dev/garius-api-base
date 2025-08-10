using System.ComponentModel.DataAnnotations;

namespace GariusWeb.Api.Configuration
{
    public class AppSecrets
    {
        public class ConnectionStringSettings
        {
            [Required(ErrorMessage = "A connection string padrão ('Development') é obrigatória.")]
            public string Development { get; set; } = string.Empty;

            [Required(ErrorMessage = "A connection string padrão ('Production') é obrigatória.")]
            public string Production { get; set; } = string.Empty;

            public string Build { get; set; } = string.Empty;
        }

        public class GoogleExternalAuthSettings
        {
            [Required(ErrorMessage = "O 'ClientId' do Google é obrigatório.")]
            public string ClientId { get; set; } = string.Empty;

            [Required(ErrorMessage = "O 'ClientSecret' do Google é obrigatório.")]
            public string ClientSecret { get; set; } = string.Empty;
        }

        public class MicrosoftExternalAuthSettings
        {
            [Required(ErrorMessage = "O 'ClientId' da Microsoft é obrigatório.")]
            public string ClientId { get; set; } = string.Empty;

            [Required(ErrorMessage = "O 'ClientSecret' da Microsoft é obrigatório.")]
            public string ClientSecret { get; set; } = string.Empty;

            [Required(ErrorMessage = "O 'TenantId' da Microsoft é obrigatório.")]
            public string TenantId { get; set; } = string.Empty;
        }

        public class CloudflareSettings
        {
            [Required(ErrorMessage = "A chave pública 'SiteKey' do Cloudflare é obrigatória.")]
            public string SiteKey { get; set; } = string.Empty;

            [Required(ErrorMessage = "A chave secreta 'SecretKey' do Cloudflare é obrigatória.")]
            public string SecretKey { get; set; } = string.Empty;
        }

        public class CloudinarySettings
        {
            [Required(ErrorMessage = "O 'CloudName' do Cloudinary é obrigatório.")]
            public string CloudName { get; set; } = string.Empty;

            [Required(ErrorMessage = "A 'ApiKey' do Cloudinary é obrigatória.")]
            public string ApiKey { get; set; } = string.Empty;

            [Required(ErrorMessage = "A 'ApiSecret' do Cloudinary é obrigatória.")]
            public string ApiSecret { get; set; } = string.Empty;
        }

        public class ResendSettings
        {
            [Required(ErrorMessage = "A 'ApiKey' do Resend é obrigatória.")]
            public string ApiKey { get; set; } = string.Empty;

            [Required(ErrorMessage = "O e-mail de envio padrão ('FromEmail') do Resend é obrigatório.")]
            [EmailAddress(ErrorMessage = "O 'FromEmail' do Resend deve ser um endereço de e-mail válido.")]
            public string FromEmail { get; set; } = string.Empty;
        }

        public class JwtSettings
        {
            [Required(ErrorMessage = "A chave secreta do JWT ('Secret') é obrigatória.")]
            public string Secret { get; set; } = string.Empty;

            [Required(ErrorMessage = "O emissor do JWT ('Issuer') é obrigatório.")]
            public string Issuer { get; set; } = string.Empty;

            [Range(1, 1440, ErrorMessage = "O tempo de expiração do JWT ('ExpirationInMinutes') deve estar entre 1 e 1440 minutos.")]
            public int ExpirationInMinutes { get; set; }

            [Required(ErrorMessage = "A audiência do JWT ('Audience') é obrigatória.")]
            public string Audience { get; set; } = string.Empty;

            public string EmailConfirmationUrl { get; set; } = default!;
            public string PasswordResetUrl { get; set; } = default!;
        }
    }
}
