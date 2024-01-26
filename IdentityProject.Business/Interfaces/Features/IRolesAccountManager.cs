namespace IdentityProject.Business.Interfaces.Features;
public interface IRolesAccountManager
{
    Task<List<Microsoft.AspNetCore.Identity.IdentityRole>?> GetListAsync();
}