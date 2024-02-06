using IdentityProject.Common.Dto;

namespace IdentityProject.Business.Interfaces.Services.Roles;
public interface IRolesService
{
    Task<List<RoleDto>?> GetListRolesAsync();
    Task<RoleDto?> GetRoleByIdAsync(string id);
    Task<List<UserRolesDto>?> GetListUserRolesAsync();
}