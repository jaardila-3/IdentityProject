using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.DataAccess.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.DataAccess.Repositories.Identity;
public class RolesRepository(ApplicationDbContext context) : IRolesRepository
{
    public async Task<List<IdentityRole>?> GetListRolesAsync() => await context.Roles.ToListAsync();
    public async Task<IdentityRole?> GetRoleByIdAsync(string id) => await context.Roles.FindAsync(id);
    public async Task<List<IdentityUserRole<string>>?> GetListUserRolesAsync() => await context.UserRoles.ToListAsync();

    public async Task<IdentityUserRole<string>?> GetUserRolesByUserIdAsync(string userId) => await context.UserRoles.FirstOrDefaultAsync(ur => ur.UserId == userId);
}