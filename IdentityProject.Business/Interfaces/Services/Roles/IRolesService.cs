namespace IdentityProject.Business.Interfaces.Services.Roles;
public interface IRolesService
{
    Task<List<Microsoft.AspNetCore.Identity.IdentityRole>?> GetListAsync();
}