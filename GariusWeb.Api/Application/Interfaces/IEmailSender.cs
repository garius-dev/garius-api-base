namespace GariusWeb.Api.Application.Interfaces
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string toEmail, string subject, string contentHtml);
    }
}
