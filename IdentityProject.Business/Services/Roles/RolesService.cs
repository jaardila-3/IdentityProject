using IdentityProject.Business.Interfaces.Services.Roles;
using IdentityProject.Common.Dto;
using IdentityProject.DataAccess.Interfaces.Repositories;

namespace IdentityProject.Business.Services.Roles;
public class RolesService(IUnitOfWork unitOfWork) : IRolesService
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;

    public async Task<List<RoleDto>?> GetListRolesAsync()
    {
        var roles = await _unitOfWork.RolesRepository.GetListRolesAsync() ?? [];
        return roles.Select(r => new RoleDto(r.Id, r.Name)).ToList();
    }

    public async Task<RoleDto?> GetRoleByIdAsync(string id)
    {
        var role = await _unitOfWork.RolesRepository.GetRoleByIdAsync(id);
        if (role is null) return null;
        var roleDto = new RoleDto(role.Id, role.Name);
        return roleDto;
    }

    public async Task<List<UserRolesDto>?> GetListUserRolesAsync()
    {
        var userRoles = await _unitOfWork.RolesRepository.GetListUserRolesAsync() ?? [];
        return userRoles.Select(ur => new UserRolesDto(ur.UserId, ur.RoleId)).ToList();
    }

    public async Task<UserRolesDto?> GetUserRolesByUserIdAsync(string userId)
    {
        var userRole = await _unitOfWork.RolesRepository.GetUserRolesByUserIdAsync(userId);
        if (userRole is null) return null;
        return new UserRolesDto(userRole.UserId, userRole.RoleId);
    }

}