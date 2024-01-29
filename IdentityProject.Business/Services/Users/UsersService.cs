using IdentityProject.Business.Exceptions;
using IdentityProject.Business.Interfaces.Services.Users;
using IdentityProject.Common.Dto;
using IdentityProject.Common.Mapper.MapperExtensions;
using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.Domain.Entities;

namespace IdentityProject.Business.Services.Users;
public class UsersService(IUnitOfWork unitOfWork) : IUsersService
{
    private readonly IUnitOfWork _unitOfWork = unitOfWork;

    public async Task<UserDto?> FindByIdAsync(string id)
    {
        var userEntity = await _unitOfWork.Repository<AppUser>()!.GetByIdAsync(id)
            ?? throw new UserNotFoundException("Usuario no encontrado.");

        return userEntity.ToDto();
    }
}