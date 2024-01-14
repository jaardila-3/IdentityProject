using IdentityProject.Domain.Entities;

namespace IdentityProject.Web.Models.MapperExtensions
{
    public static class MapperUser
    {
        public static AppUser ToDomain(this RegisterViewModel model)
        {
            return new AppUser
            {
                UserName = model.UserName,
                Email = model.Email,
                Name = model.Name,
                Address = model.Address,
                Birthdate = model.Birthdate,
                Country = model.Country,
                CountryCode = model.CountryCode,
                City = model.City,
                Url = model.Url,
                PhoneNumber = model.PhoneNumber,
            };
        }
    }
}