using IdentityProject.Business.Interfaces.Services.Roles;
using IdentityProject.Common.Dto;
using IdentityProject.DataAccess.Interfaces.Repositories;

namespace IdentityProject.Business.Services.Roles;
public class RolesService(IUnitOfWork unitOfWork) : IRolesService
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;

    public async Task<List<RoleDto>?> GetListAsync()
    {
        var roles = await _unitOfWork.RolesRepository.GetListAsync() ?? [];
        var rolesDto = roles.Select(r => new RoleDto(r.Id, r.Name)).ToList();
        return rolesDto;
    }

    public async Task<RoleDto?> GetByIdAsync(string id)
    {
        var role = await _unitOfWork.RolesRepository.GetByIdAsync(id);
        if (role is null) return null;
        var roleDto = new RoleDto(role.Id, role.Name);
        return roleDto;
    }

}