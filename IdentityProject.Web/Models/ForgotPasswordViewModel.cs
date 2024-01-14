
using System.ComponentModel.DataAnnotations;

namespace IdentityProject.Web.Models
{
    public record ForgotPasswordViewModel
    {
        [Required(ErrorMessage = "El {0} es obligatorio")]
        [EmailAddress]
        [Display(Name = "Correo electrónico")]
        [DataType(DataType.EmailAddress)]
        public string? Email { get; set; }
    }
}