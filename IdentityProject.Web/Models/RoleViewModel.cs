using System.ComponentModel.DataAnnotations;

namespace IdentityProject.Web.Models;
public class RoleViewModel
{
    public string? Id { get; set; }

    [Required(ErrorMessage = "El {0} es obligatorio")]
    [StringLength(50, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 5)]
    [RegularExpression(@"^[a-zA-Z0-9 _-]+$", ErrorMessage = "El {0} solo puede contener letras y números.")]
    [DataType(DataType.Text)]
    [Display(Name = "Nombre del Rol")]
    public string? Name { get; set; }
}