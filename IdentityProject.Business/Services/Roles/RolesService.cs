using IdentityProject.Business.Interfaces.Services.Roles;
using IdentityProject.DataAccess.Interfaces.Repositories;

namespace IdentityProject.Business.Services.Roles;
public class RolesService(IUnitOfWork unitOfWork) : IRolesService
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;

    public async Task<List<Microsoft.AspNetCore.Identity.IdentityRole>?> GetListAsync() => await _unitOfWork.RolesRepository.GetListAsync();

}