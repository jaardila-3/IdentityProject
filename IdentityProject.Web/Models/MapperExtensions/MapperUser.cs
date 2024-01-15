using IdentityProject.Common.Dto;

namespace IdentityProject.Web.Models.MapperExtensions
{
    public static class MapperUser
    {
        public static UserDto ToDto(this RegisterViewModel model)
        {
            return new UserDto(model.UserName, model.Email, model.Name, model.Url, model.CountryCode, model.PhoneNumber, model.Country, model.City, model.Address, model.Birthdate, model.State);
        }
    }
}