using IdentityProject.Services.SMTP.MailJet;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityProject.Services;
public static class DependencyInjectionRegistration
{
    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        //add IoC
        //Transient
        services.AddTransient<IEmailSender, MailJetEmailSender>();
        return services;
    }
}