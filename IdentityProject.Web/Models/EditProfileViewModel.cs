using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdentityProject.Web.Models
{
    public record EditProfileViewModel
    {
        [Required]
        public string? Id { get; set; }

        [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.Text)]
        [Display(Name = "Usuario")]
        public string? UserName { get; set; }

        [EmailAddress]
        [Display(Name = "Correo electrónico")]
        [DataType(DataType.EmailAddress)]
        public string? Email { get; set; }        

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [StringLength(50, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 7)]
        [DataType(DataType.Text)]
        [Display(Name = "Nombre")]
        public string? Name { get; set; }

        [StringLength(40, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.Url)]
        [Display(Name = "Página web")]
        public string? Url { get; set; }

        [Range(1, 999)]
        [Display(Name = "Código país")]
        public int? CountryCode { get; set; }

        [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.PhoneNumber)]
        [Display(Name = "Teléfono")]
        public string? PhoneNumber { get; set; }

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 3)]
        [DataType(DataType.Text)]
        [Display(Name = "País")]
        public string? Country { get; set; }

        [StringLength(30, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 3)]
        [DataType(DataType.Text)]
        [Display(Name = "Ciudad")]
        public string? City { get; set; }

        [StringLength(40, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.Text)]
        [Display(Name = "Dirección")]
        public string? Address { get; set; }

        [Display(Name = "Fecha de Nacimiento")]
        [DataType(DataType.Date)]
        public DateTime? Birthdate { get; set; }

        public bool State { get; set; }
    }
}