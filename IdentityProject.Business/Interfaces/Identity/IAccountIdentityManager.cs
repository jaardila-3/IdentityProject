using System.Security.Claims;
using IdentityProject.Common.Dto;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Business.Interfaces.Identity;

public interface IAccountIdentityManager
{
    #region Users
    Task<(ResultDto result, string userId)> CreateUserAsync(UserDto user, string password);
    Task<ResultDto> AddUserToRoleAsync(string userId, string role);
    Task<string> GenerateEmailConfirmationTokenAsync(string userId);
    Task<ResultDto> ConfirmEmailAsync(string userId, string token);
    Task<string?> FindByEmailAsync(string email);
    Task<string> GeneratePasswordResetTokenAsync(string userId);
    Task<ResultDto> ResetPasswordAsync(string userId, string token, string newPassword);
    Task<string?> GetUserAsync(ClaimsPrincipal principal);
    Task<bool> IsTwoFactorEnabled(ClaimsPrincipal principal);
    Task<ResultDto> ResetAuthenticatorKeyAsync(string userId);
    Task<string?> GetAuthenticatorKeyAsync(string userId);
    Task<bool> VerifyTwoFactorTokenAsync(string userId, string token);
    Task<ResultDto> SetTwoFactorEnabledAsync(string userId, bool enabled);
    Task<ResultDto> UpdateUserAsync(UserDto userDto);
    Task DeleteUserAsync(string userId);
    #endregion

    #region SignIn
    Task SignInAsync(string userId, bool isPersistent, string? authenticationMethod = null);
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
}
