using System.Security.Claims;
using IdentityProject.Common.Dto;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Business.Interfaces.Identity;

public interface IIdentityManager
{
    #region Users
    Task<(IdentityResult, string)> CreateUserAsync(UserDto user, string password);
    Task<IdentityResult> AddToRoleAsync(IdentityUser user, string role);
    Task<IdentityUser?> FindByIdAsync(string userId);
    Task<string> GenerateEmailConfirmationTokenAsync(IdentityUser user);
    Task<IdentityResult> ConfirmEmailAsync(IdentityUser user, string token);
    Task<IdentityUser?> FindByEmailAsync(string email);
    Task<string> GeneratePasswordResetTokenAsync(IdentityUser user);
    Task<IdentityResult> ResetPasswordAsync(IdentityUser user, string token, string newPassword);
    Task<IdentityUser?> GetUserAsync(ClaimsPrincipal principal);
    Task<IdentityResult> ResetAuthenticatorKeyAsync(IdentityUser user);
    Task<string?> GetAuthenticatorKeyAsync(IdentityUser user);
    Task<bool> VerifyTwoFactorTokenAsync(IdentityUser user, string token);
    Task<IdentityResult> SetTwoFactorEnabledAsync(IdentityUser user, bool enabled);
    Task<IdentityResult> UpdateUserAsync(UserDto userDto);
    #endregion

    #region SignIn
    Task SignInAsync(IdentityUser user, bool isPersistent, string? authenticationMethod = null);
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
