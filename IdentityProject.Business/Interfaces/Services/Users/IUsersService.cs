using IdentityProject.Common.Dto;

namespace IdentityProject.Business.Interfaces.Services.Users;
public interface IUsersService
{
    Task<UserDto?> FindUserByIdAsync(string id);
    Task<List<UserDto>?> GetListUsersAsync();
}