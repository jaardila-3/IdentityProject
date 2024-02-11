using System.Security.Claims;
using IdentityProject.Web.Enums;

namespace IdentityProject.Web.Claims;
public static class ClaimsManager
{
    public static readonly List<Claim> ClaimsCollection =
    [
        new Claim(nameof(UserClaimType.Create), true.ToString()),
        new Claim(nameof(UserClaimType.Edit), true.ToString()),
        new Claim(nameof(UserClaimType.Delete), true.ToString()),
    ];
}