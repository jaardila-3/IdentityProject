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
        [Display(Name = "Correo electrónico")]
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
        [Display(Name = "Nombre")]
        public string Name { get; set; } = string.Empty;

        [Display(Name = "Página web")]
        public string Url { get; set; } = string.Empty;

        [Display(Name = "Código país")]
        public int CountryCode { get; set; }

        [Display(Name = "Teléfono")]
        public string PhoneNumber { get; set; } = string.Empty;

        [Required(ErrorMessage = "El país es obligatorio")]
        [Display(Name = "País")]
        public string Country { get; set; } = string.Empty;

        [Display(Name = "Ciudad")]
        public string City { get; set; } = string.Empty;

        [Display(Name = "Dirección")]
        public string Address { get; set; } = string.Empty;

        [Required(ErrorMessage = "La Fecha de Nacimiento es obligatoria")]
        [Display(Name = "Fecha de Nacimiento")]
        public DateTime Birthdate { get; set; }
    }
}