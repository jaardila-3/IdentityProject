using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.DataAccess.Persistence;
using Microsoft.EntityFrameworkCore;

namespace IdentityProject.DataAccess.Repositories.Identity;
public class RolesRepository(ApplicationDbContext context) : IRolesRepository
{
    public async Task<List<Microsoft.AspNetCore.Identity.IdentityRole>?> GetListAsync() => await context.Roles.ToListAsync();
}