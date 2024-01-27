using IdentityProject.Common.Dto;

namespace IdentityProject.Business.Interfaces.Services.Users;
public interface IUsersService
{
    Task<UserDto?> FindByIdAsync(string id);
}