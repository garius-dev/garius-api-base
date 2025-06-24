using GariusWeb.Api.Application.Exceptions;
using GariusWeb.Api.Application.Interfaces;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Text;
using static GariusWeb.Api.Configuration.AppSecrets;

namespace GariusWeb.Api.Infrastructure.Services
{
    public class ResendEmailSender : IEmailSender
    {
        private readonly HttpClient _httpClient;
        private readonly ResendSettings _settings;

        public ResendEmailSender(HttpClient httpClient, IOptions<ResendSettings> settings)
        {
            _httpClient = httpClient;
            _settings = settings.Value;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string contentHtml)
        {
            var payload = new
            {
                from = _settings.FromEmail,
                to = new[] { toEmail },
                subject,
                html = contentHtml
            };

            var request = new HttpRequestMessage(HttpMethod.Post, "https://api.resend.com/emails")
            {
                Content = new StringContent(JsonConvert.SerializeObject(payload), Encoding.UTF8, "application/json")
            };

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _settings.ApiKey);

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                throw new ServiceUnavailableException("Falha ao enviar e-mail de confirmação.");
            }
        }
    }
}
