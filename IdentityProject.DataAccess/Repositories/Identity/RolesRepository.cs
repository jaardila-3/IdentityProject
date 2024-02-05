using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.DataAccess.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.DataAccess.Repositories.Identity;
public class RolesRepository(ApplicationDbContext context) : IRolesRepository
{
    public async Task<List<IdentityRole>?> GetListAsync() => await context.Roles.ToListAsync();
    public async Task<IdentityRole?> GetByIdAsync(string id) => await context.Roles.FindAsync(id);
}