using IdentityProject.Common.Dto;

namespace IdentityProject.Business.Interfaces.Features
{
    public interface IUserManager
    {
        Task<UserDto?> FindByIdAsync(string id);
    }
}