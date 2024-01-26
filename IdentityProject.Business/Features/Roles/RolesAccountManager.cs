using IdentityProject.Business.Interfaces.Features;
using IdentityProject.DataAccess.Interfaces.Repositories;

namespace IdentityProject.Business.Features.Roles;
public class RolesAccountManager(IUnitOfWork unitOfWork) : IRolesAccountManager
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;

    public async Task<List<Microsoft.AspNetCore.Identity.IdentityRole>?> GetListAsync() => await _unitOfWork.RolesRepository.GetListAsync();

}