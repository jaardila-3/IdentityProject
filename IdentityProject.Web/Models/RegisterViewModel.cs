using System.ComponentModel.DataAnnotations;

namespace IdentityProject.Web.Models
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "El nombre de usuario es obligatorio")]
        [StringLength(20, ErrorMessage = "El {0} debe ser al menos {2} y máximo {1} caracteres", MinimumLength = 5)]
        [Display(Name = "Usuario")]
        public string UserName { get; set; }

        [Required(ErrorMessage = "El Email es obligatorio")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [StringLength(50, ErrorMessage = "El {0} debe ser al menos {2} y máximo {1} caracteres", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [Required(ErrorMessage = "La confirmación de la contraseña es obligatoria")]
        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirmar Contraseña")]
        public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "El nombre es obligatorio")]
        public string Name { get; set; }

        public string Url { get; set; }
        public int CountryCode { get; set; }
        public string PhoneNumber { get; set; }

        [Required(ErrorMessage = "El país es obligatorio")]
        public string Country { get; set; }
        public string City { get; set; }
        public string Address { get; set; }

        [Required(ErrorMessage = "La Fecha de Nacimiento es obligatoria")]
        public DateTime Birthdate { get; set; }
    }
}