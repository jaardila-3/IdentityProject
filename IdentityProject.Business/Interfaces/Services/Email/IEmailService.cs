namespace IdentityProject.Business.Interfaces.Services.Email;
public interface IEmailService
{
    Task SendEmailAsync(string email, string subject, string message);
}