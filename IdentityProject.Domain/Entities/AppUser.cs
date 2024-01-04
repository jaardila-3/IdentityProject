using System;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Domain.Entities
{
    public class AppUser : IdentityUser
    {
        public string Name { get; set; } = string.Empty;
        public string Url { get; set; } = string.Empty;
        public int CountryCode { get; set; }
        public string Country { get; set; } = string.Empty;
        public string City { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;
        public DateTime Birthdate { get; set; }
        public bool State { get; set; }
    }
}