using IdentityProject.Business.identity;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Email;
using IdentityProject.Business.Interfaces.Services.Roles;
using IdentityProject.Business.Interfaces.Services.Users;
using IdentityProject.Business.Services.Email;
using IdentityProject.Business.Services.Roles;
using IdentityProject.Business.Services.Users;
using IdentityProject.Services;
using IdentityProject.DataAccess;
using IdentityProject.DataAccess.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityProject.Business;
public static class DependencyInjectionRegistration
{
    public static IServiceCollection AddBusinessServices(this IServiceCollection services, IConfiguration configuration)
    {
        //Add services from other layers
        services.AddDataAccessServices(configuration);
        services.AddExternalServices();

        //add identity service
        services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();
        //configuration options for identity
        services.Configure<IdentityOptions>(options =>
        {
            // Password settings.
            options.Password.RequireDigit = true;
            options.Password.RequireLowercase = true;
            options.Password.RequireNonAlphanumeric = true;
            options.Password.RequireUppercase = true;
            options.Password.RequiredLength = 8;
            options.Password.RequiredUniqueChars = 1;
            //lockout settings.
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(60);
            options.Lockout.MaxFailedAccessAttempts = 3;
            options.Lockout.AllowedForNewUsers = true;
            // User settings.
            options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
            options.User.RequireUniqueEmail = true;
            //SignIn settings
            //options.SignIn.RequireConfirmedEmail = true;
        });

        //add IoC
        //Transient
        services.AddTransient<IAccountIdentityManager, AccountIdentityManager>();
        services.AddTransient<IEmailService, EmailService>();
        //Scoped
        services.AddScoped<IUsersService, UsersService>();
        services.AddScoped<IRolesService, RolesService>();

        return services;
    }
}