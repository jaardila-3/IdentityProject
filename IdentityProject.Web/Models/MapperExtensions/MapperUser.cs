using IdentityProject.Common.Dto;

namespace IdentityProject.Web.Models.MapperExtensions
{
    public static class MapperUser
    {
        public static UserDto ToDto(this RegisterViewModel model)
        {
            return new UserDto(string.Empty, model.UserName, model.Email, model.Name, model.Url, model.CountryCode, model.PhoneNumber, model.Country, model.City, model.Address, model.Birthdate, model.State);
        }

        public static EditProfileViewModel ToViewModel(this UserDto dto)
        {
            return new EditProfileViewModel
            {
                Id = dto.Id,
                Email = dto.Email,
                UserName = dto.UserName,
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

        public static UserDto ToDto(this EditProfileViewModel model)
        {
            return new UserDto(model.Id, model.UserName, model.Email, model.Name, model.Url, model.CountryCode, model.PhoneNumber, model.Country, model.City, model.Address, model.Birthdate, model.State);
        }
    }
}