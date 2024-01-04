using System.ComponentModel.DataAnnotations;

namespace IdentityProject.Web.Models
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "El nombre de usuario es obligatorio")]
        [StringLength(20, ErrorMessage = "El {0} debe tener al menos {2} caracteres y máximo {1}", MinimumLength = 5)]
        [Display(Name = "Usuario")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "El Email es obligatorio")]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [StringLength(50, ErrorMessage = "La {0} debe tener al menos {2} caracteres y máximo {1}", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "La confirmación de la contraseña es obligatoria")]
        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirmar Contraseña")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "El nombre es obligatorio")]
        public string Name { get; set; } = string.Empty;

        public string Url { get; set; } = string.Empty;
        public int CountryCode { get; set; }
        public string PhoneNumber { get; set; } = string.Empty;

        [Required(ErrorMessage = "El país es obligatorio")]
        public string Country { get; set; } = string.Empty;
        public string City { get; set; } = string.Empty;
        public string Address { get; set; } = string.Empty;

        [Required(ErrorMessage = "La Fecha de Nacimiento es obligatoria")]
        public DateTime Birthdate { get; set; }
    }
}