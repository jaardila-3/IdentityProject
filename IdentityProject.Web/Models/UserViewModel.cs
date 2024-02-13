using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdentityProject.Web.Models;
public record UserViewModel
{
    [Required]
    [StringLength(50, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 15)]
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

    [Display(Name = "Roles para asignar al usuario")]
    public string? RoleId { get; set; }
    public IEnumerable<SelectListItem>? RolesApp { get; set; }

    [Display(Name = "Roles del usuario")]
    public IEnumerable<RoleViewModel>? CurrentRoles { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; } = null;
}