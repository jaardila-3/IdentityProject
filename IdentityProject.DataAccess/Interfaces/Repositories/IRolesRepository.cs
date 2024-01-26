namespace IdentityProject.DataAccess.Interfaces.Repositories;
public interface IRolesRepository
{
    Task<List<Microsoft.AspNetCore.Identity.IdentityRole>?> GetListAsync();
}