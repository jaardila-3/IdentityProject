using Microsoft.AspNetCore.Identity;

namespace IdentityProject.DataAccess.Interfaces.Repositories;
public interface IRolesRepository
{
    Task<List<IdentityRole>?> GetListRolesAsync();
    Task<IdentityRole?> GetRoleByIdAsync(string id);
    Task<List<IdentityUserRole<string>>?> GetListUserRolesAsync();
    Task<List<IdentityUserRole<string>>?> GetUserRolesByUserIdAsync(string userId);
}