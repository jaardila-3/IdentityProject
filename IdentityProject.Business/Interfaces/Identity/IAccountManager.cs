using System.Security.Claims;
using IdentityProject.Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Business.Interfaces.Identity
{
    public interface IAccountManager
    {
        #region Users
        Task<IdentityResult> CreateUserAsync(AppUser user, string password);
        Task<IdentityResult> AddToRoleAsync(AppUser user, string role);
        Task<IdentityUser?> FindByIdAsync(string userId);
        Task<IdentityResult> ConfirmEmailAsync(IdentityUser user, string token);
        Task<IdentityUser?> FindByEmailAsync(string email);
        Task<string> GeneratePasswordResetTokenAsync(IdentityUser user);
        Task<IdentityResult> ResetPasswordAsync(IdentityUser user, string token, string newPassword);
        Task<string> GenerateEmailConfirmationTokenAsync(AppUser user);
        Task<IdentityUser?> GetUserAsync(ClaimsPrincipal principal);
        Task<IdentityResult> ResetAuthenticatorKeyAsync(IdentityUser user);
        Task<string?> GetAuthenticatorKeyAsync(IdentityUser user);
        Task<bool> VerifyTwoFactorTokenAsync(IdentityUser user, string token);
        Task<IdentityResult> SetTwoFactorEnabledAsync(IdentityUser user, bool enabled);
        #endregion

        #region SignIn
        Task SignInAsync(AppUser user, bool isPersistent, string? authenticationMethod = null);
        Task SignOutAsync();
        Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure);
        Task<IdentityUser?> GetTwoFactorAuthenticationUserAsync();
        Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient);
        #endregion

        #region Roles
        Task<bool> RoleExistsAsync(string roleName);
        Task<IdentityResult> CreateRoleAsync(IdentityRole role);
        Task<List<IdentityRole>?> GetRolesListAsync();
        #endregion

        #region Helpers
        Task CreateRolesAsync();
        #endregion
    }
}