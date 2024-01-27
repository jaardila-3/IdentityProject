using System.Security.Claims;
using IdentityProject.Common.Dto;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Business.Interfaces.Identity;

public interface IAccountIdentityManager
{
    #region Users
    Task<(ResultDto result, string userId)> CreateUserAsync(UserDto user, string password);
    Task<ResultDto> AddUserToRoleAsync(string userId, string role);
    Task<IdentityUser?> FindByIdAsync(string userId);
    Task<string> GenerateEmailConfirmationTokenAsync(string userId);
    Task<ResultDto> ConfirmEmailAsync(string userId, string token);
    Task<string?> FindByEmailAsync(string email);
    Task<string> GeneratePasswordResetTokenAsync(string userId);
    Task<IdentityResult> ResetPasswordAsync(IdentityUser user, string token, string newPassword);
    Task<IdentityUser?> GetUserAsync(ClaimsPrincipal principal);
    Task<IdentityResult> ResetAuthenticatorKeyAsync(IdentityUser user);
    Task<string?> GetAuthenticatorKeyAsync(IdentityUser user);
    Task<bool> VerifyTwoFactorTokenAsync(IdentityUser user, string token);
    Task<IdentityResult> SetTwoFactorEnabledAsync(IdentityUser user, bool enabled);
    Task<IdentityResult> UpdateUserAsync(UserDto userDto);
    Task DeleteUserAsync(string userId);
    #endregion

    #region SignIn
    Task SignInAsync(string userId, bool isPersistent, string? authenticationMethod = null);
    Task SignOutAsync();
    Task<ResultDto> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure);
    Task<IdentityUser?> GetTwoFactorAuthenticationUserAsync();
    Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient);
    #endregion

    #region Roles
    Task<bool> RoleExistsAsync(string roleName);
    Task<IdentityResult> CreateRoleAsync(IdentityRole role);
    Task<List<string?>?> GetRolesAsync();
    #endregion

    #region Helpers
    Task CreateRolesAsync();
    #endregion
}
