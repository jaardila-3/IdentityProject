using Microsoft.AspNetCore.Identity;

namespace IdentityProject.DataAccess.Interfaces.Repositories;
public interface IRolesRepository
{
    Task<List<IdentityRole>?> GetListAsync();
    Task<IdentityRole?> GetByIdAsync(string id);
}