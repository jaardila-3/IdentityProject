using IdentityProject.Common.Dto;
using IdentityProject.Domain.Entities;

namespace IdentityProject.Common.Mapper.MapperExtensions
{
    public static class MapperUser
    {
        public static AppUser ToDomain(this UserDto dto)
        {
            return new AppUser
            {
                UserName = dto.UserName,
                Email = dto.Email,
                Name = dto.Name,
                Url = dto.Url,
                CountryCode = dto.CountryCode,
                PhoneNumber = dto.PhoneNumber,
                Country = dto.Country,
                City = dto.City,
                Address = dto.Address,
                Birthdate = dto.Birthdate,
                State = dto.State
            };
        }
    }
}