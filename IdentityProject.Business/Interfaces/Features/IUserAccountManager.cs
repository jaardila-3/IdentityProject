using IdentityProject.Common.Dto;

namespace IdentityProject.Business.Interfaces.Features
{
    public interface IUserAccountManager
    {
        Task<UserDto?> FindByIdAsync(string id);
    }
}