using System.ComponentModel.DataAnnotations;

namespace IdentityProject.Web.Models
{
    public class VerifyAuthenticatorCodeViewModel
    {
        [Required(ErrorMessage = "El {0} es obligatorio")]
        [Display(Name = "Código del autenticador de dos factores")]
        public string Code { get; set; } = string.Empty;

        public string? ReturnUrl { get; set; }

        [Display(Name = "Recordar datos")]
        public bool RememberMe { get; set; }

    }
}