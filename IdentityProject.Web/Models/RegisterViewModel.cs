using System.ComponentModel.DataAnnotations;

namespace IdentityProject.Web.Models
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "El {0} es obligatorio")]
        [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.Text)]        
        [Display(Name = "Usuario")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [EmailAddress]
        [Display(Name = "Correo electrónico")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [StringLength(50, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "La confirmación de la contraseña es obligatoria")]
        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirmar Contraseña")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [StringLength(50, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 7)]
        [DataType(DataType.Text)]
        [Display(Name = "Nombre")]
        public string Name { get; set; } = string.Empty;

        [StringLength(40, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.Url)]      
        [Display(Name = "Página web")]
        public string Url { get; set; } = string.Empty;

        [Range(1, 999)]
        [Display(Name = "Código país")]
        public int CountryCode { get; set; }

        [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.PhoneNumber)]
        [Display(Name = "Teléfono")]
        public string PhoneNumber { get; set; } = string.Empty;

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 3)]
        [DataType(DataType.Text)]
        [Display(Name = "País")]
        public string Country { get; set; } = string.Empty;

        [StringLength(30, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 3)]
        [DataType(DataType.Text)]
        [Display(Name = "Ciudad")]
        public string City { get; set; } = string.Empty;

        [StringLength(40, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.Text)]
        [Display(Name = "Dirección")]
        public string Address { get; set; } = string.Empty;

        [Required(ErrorMessage = "La {0} es obligatoria")]
        [Display(Name = "Fecha de Nacimiento")]
        [DataType(DataType.Date)]
        public DateTime Birthdate { get; set; }
        
    }
}