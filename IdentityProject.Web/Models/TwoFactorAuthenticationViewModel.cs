using System.ComponentModel.DataAnnotations;

namespace IdentityProject.Web.Models
{
    public class TwoFactorAuthenticationViewModel
    {
        [Required(ErrorMessage = "El {0} es obligatorio")]
        [Display(Name = "Token")]
        public string? Token { get; set; }

        [Required(ErrorMessage = "El {0} es obligatorio")]
        [Display(Name = "Código del autenticador de dos factores")]
        public string? Code { get; set; }

        //QR code
        public string? QrCodeUri { get; set; }
    }
}