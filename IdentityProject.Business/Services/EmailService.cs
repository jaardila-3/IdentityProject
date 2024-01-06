using Microsoft.AspNetCore.Identity.UI.Services;
using IdentityProject.Business.Interfaces.Services;

namespace IdentityProject.Business.Services
{
    public class EmailService : IEmailService
    {
        private readonly IEmailSender _emailSender;

        public EmailService(IEmailSender emailSender)
        {
            _emailSender = emailSender;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            await _emailSender.SendEmailAsync(email, subject, message);
        }
    }
}