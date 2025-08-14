using Ganss.Xss;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using System.Text;

namespace GariusWeb.Api.Extensions
{
    public static class TextExtensions
    {
        private static readonly HtmlSanitizer _sanitizer = new HtmlSanitizer();

        public static string CreateOneTimeCode(int byteLen = 32)
        {
            if (byteLen < 32) throw new ArgumentOutOfRangeException(nameof(byteLen), "Use >= 32 bytes.");
            Span<byte> bytes = stackalloc byte[byteLen];
            RandomNumberGenerator.Fill(bytes);
            return WebEncoders.Base64UrlEncode(bytes);
        }

        public static bool TryGetCodeHash(string? code, out string hexHash)
        {
            hexHash = string.Empty;
            if (string.IsNullOrWhiteSpace(code)) return false;

            if (code.Length > 512) return false;

            try
            {
                byte[] codeBytes = WebEncoders.Base64UrlDecode(code);
                byte[] hash = SHA256.HashData(codeBytes);
                hexHash = Convert.ToHexString(hash);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static string SanitizeInput(this string input)
        {
            return string.IsNullOrEmpty(input)
                ? string.Empty
                : _sanitizer.Sanitize(input);
        }

        public static string ToFormattedErrorString(this ModelStateDictionary modelState)
        {
            if (modelState == null || modelState.IsValid)
                return string.Empty;

            var sb = new StringBuilder();

            foreach (var entry in modelState)
            {
                var fieldKey = entry.Key;
                var errors = entry.Value.Errors;

                foreach (var error in errors)
                {
                    // Se ErrorMessage estiver vazio, usa Exception.Message (fallback)
                    var errorMessage = !string.IsNullOrWhiteSpace(error.ErrorMessage)
                        ? error.ErrorMessage
                        : error.Exception?.Message ?? "Erro desconhecido";

                    // Formata: Campo - Mensagem.
                    sb.Append($"{errorMessage}; ");
                }
            }

            // Remove o último "; " se houver
            if (sb.Length >= 2)
                sb.Length -= 2;

            return sb.ToString();
        }

    }
}
