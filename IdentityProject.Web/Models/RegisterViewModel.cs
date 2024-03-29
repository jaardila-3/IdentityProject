using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdentityProject.Web.Models
{
    public record RegisterViewModel
    {
        [Required(ErrorMessage = "El {0} es obligatorio")]
        [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
        [DataType(DataType.Text)]
        [Display(Name = "Usuario")]
        public string? UserName { get; set; }

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [EmailAddress]
        [Display(Name = "Correo electrónico")]
        [DataType(DataType.EmailAddress)]
        public string? Email { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [StringLength(50, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string? Password { get; set; }

        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirmar Contraseña")]
        public string? ConfirmPassword { get; set; }

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [StringLength(50, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 7)]
        [RegularExpression(@"^[a-zA-Z0-9\u00E0-\u00FC ]+$", ErrorMessage = "{0} solo puede contener letras y números.")]
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
        [RegularExpression(@"^[0-9 +()]+$", ErrorMessage = "{0} solo puede contener caracteres válidos.")]
        [DataType(DataType.PhoneNumber)]
        [Display(Name = "Teléfono")]
        public string? PhoneNumber { get; set; }

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [StringLength(20, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 4)]
        [RegularExpression(@"^[a-zA-Z0-9\u00E0-\u00FC ]+$", ErrorMessage = "{0} solo puede contener letras y números.")]
        [DataType(DataType.Text)]
        [Display(Name = "País")]
        public string? Country { get; set; }

        [StringLength(30, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 4)]
        [RegularExpression(@"^[a-zA-Z0-9\u00E0-\u00FC ]+$", ErrorMessage = "{0} solo puede contener letras y números.")]
        [DataType(DataType.Text)]
        [Display(Name = "Ciudad")]
        public string? City { get; set; }

        [StringLength(40, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 6)]
        [RegularExpression(@"^[a-zA-Z0-9\u00E0-\u00FC #-\.,]+$", ErrorMessage = "{0} solo puede contener caracteres válidos.")]
        [DataType(DataType.Text)]
        [Display(Name = "Dirección")]
        public string? Address { get; set; }

        [Display(Name = "Fecha de Nacimiento")]
        [DataType(DataType.Date)]
        public DateTime? Birthdate { get; set; }

        public bool State { get; set; }

        public IEnumerable<SelectListItem>? Roles { get; set; }

        [StringLength(50, ErrorMessage = "La {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 4)]
        [Display(Name = "Rol")]
        public string? SelectedRole { get; set; }
    }
}