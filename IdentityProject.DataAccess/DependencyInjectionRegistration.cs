using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.DataAccess.Persistence;
using IdentityProject.DataAccess.Repositories.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityProject.DataAccess;
public static class DependencyInjectionRegistration
{
    public static IServiceCollection AddDataAccessServices(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection");

        services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(connectionString, b => b.MigrationsAssembly("IdentityProject.DataAccess")));

        //add IoC
        //Scoped
        services.AddScoped<IUnitOfWork, UnitOfWorkIdentity>();
        services.AddScoped(typeof(IRepositoryWriteCommands<>), typeof(RepositoryIdentity<>));
        services.AddScoped<IRolesRepository, RolesRepository>();

        return services;
    }
}