using System;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Domain.Entities
{
    public class AppUser : IdentityUser
    {
        public string Name { get; set; }
        public string Url { get; set; }
        public int CountryCode { get; set; }
        public string Country { get; set; }
        public string City { get; set; }
        public string Address { get; set; }
        public DateTime Birthdate { get; set; }
        public bool State { get; set; }
    }
}