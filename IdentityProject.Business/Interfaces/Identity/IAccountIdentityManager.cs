using System.Security.Claims;
using IdentityProject.Common.Dto;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Business.Interfaces.Identity;

public interface IAccountIdentityManager
{
    #region Register
    Task<(ResultDto result, string userId)> CreateUserAsync(UserDto user, string password, string roleName, bool autoSignIn = true);
    Task<string> GenerateEmailConfirmationTokenAsync(string userId);
    Task ConfirmEmailAsync(string userId, string token);
    #endregion

    #region UserManager
    Task<string> GeneratePasswordResetTokenAsync(string userId);
    Task<ResultDto> ResetPasswordAsync(string userId, string token, string newPassword);
    Task<string?> GetUserAsync(ClaimsPrincipal principal);
    Task<bool> IsTwoFactorEnabled(ClaimsPrincipal principal);
    Task<ResultDto> UpdateUserAsync(UserDto userDto);
    #endregion

    #region SignIn
    Task SignOutAsync();
    Task<ResultDto> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure);
    Task GetTwoFactorAuthenticationUserAsync();
    Task<ResultDto> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient);
    #endregion

    #region Roles
    Task<bool> RoleExistsAsync(string roleName);
    Task<ResultDto> CreateRoleAsync(IdentityRole role);
    Task<List<string?>?> GetRolesAsync();
    #endregion

    #region Helpers
    Task CreateRolesAsync();
    #endregion

    #region Two Factor Authentication
    Task<(string token, string email)> InitiateTwoFactorAuthenticationAsync(ClaimsPrincipal User);
    Task<bool> ConfirmTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim, string authenticatorCode);
    Task DisableTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim);
    #endregion

    #region Forgot Password
    Task<(string userId, string token)> GeneratePasswordResetToken(string email);
    Task<ResultDto> ResetPassword(string email, string token, string newPassword);
    #endregion
}
