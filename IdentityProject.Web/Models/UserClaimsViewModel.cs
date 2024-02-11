using System.ComponentModel.DataAnnotations;

namespace IdentityProject.Web.Models;
public class UserClaimsViewModel
{
    [Required]
    [StringLength(50, ErrorMessage = "El {0} debe tener entre {2} y {1} caracteres.", MinimumLength = 15)]
    public string? UserId { get; set; }
    public List<ClaimApp> Claims { get; set; } = [];
}

public class ClaimApp
{
    public string? ClaimType { get; set; }
    public bool Selected { get; set; }
}