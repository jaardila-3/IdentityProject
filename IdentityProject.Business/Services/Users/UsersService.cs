using IdentityProject.Business.Interfaces.Services.Users;
using IdentityProject.Common.Dto;
using IdentityProject.Common.Mapper.MapperExtensions;
using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.Domain.Entities;

namespace IdentityProject.Business.Services.Users;
public class UsersService(IUnitOfWork unitOfWork) : IUsersService
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;

    public async Task<UserDto?> FindUserByIdAsync(string id)
    {
        var userEntity = await _unitOfWork.Repository<AppUser>()!.GetByIdAsync(id);
        if (userEntity is null) return null;
        return userEntity.ToDto();
    }

    public async Task<List<UserDto>?> GetListUsersAsync()
    {
        var userEntity = await _unitOfWork.Repository<AppUser>()!.GetListAsync() ?? [];
        return userEntity.Select(u => u.ToDto()).ToList();
    }
}