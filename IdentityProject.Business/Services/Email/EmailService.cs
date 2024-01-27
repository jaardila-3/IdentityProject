using IdentityProject.Business.Interfaces.Services.Email;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace IdentityProject.Business.Services.Email;
public class EmailService(IEmailSender emailSender) : IEmailService
{
    private readonly IEmailSender _emailSender = emailSender;

    public async Task SendEmailAsync(string email, string subject, string message) => await _emailSender.SendEmailAsync(email, subject, message);
}