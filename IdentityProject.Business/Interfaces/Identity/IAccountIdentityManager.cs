using System.Security.Claims;
using IdentityProject.Common.Dto;

namespace IdentityProject.Business.Interfaces.Identity;

public interface IAccountIdentityManager
{
    #region Register
    Task<(ResultDto result, string userId)> CreateUserAsync(UserDto user, string password, string roleName, bool autoSignIn = true);
    Task<string> GenerateEmailConfirmationTokenAsync(string userId);
    Task<bool> ConfirmEmailAsync(string userId, string token);
    #endregion

    #region Users
    Task<ResultDto> UpdateUserAsync(UserDto userDto);
    Task<ResultDto> LockAndUnlockUserAsync(string id, DateTimeOffset? endDate = null);
    Task<ResultDto> DeleteUserAsync(string id);
    Task<IList<Claim>> GetRemoveOrAssignUserClaimsByIdAsync(string id, bool removeClaims = false, IEnumerable<Claim>? assignClaims = null);
    #endregion

    #region SignIn
    Task SignOutAsync();
    Task<ResultDto> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure);
    Task GetTwoFactorAuthenticationUserAsync();
    Task<ResultDto> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient);
    #endregion

    #region Roles
    Task<ResultDto> CreateRoleAsync(string roleName);
    Task<ResultDto> UpdateRoleAsync(RoleDto roleDto);
    Task<List<string?>?> GetRolesAsync();
    Task SetupRolesAsync();
    Task<ResultDto> DeleteRoleAsync(string id);
    Task<ResultDto> AssignNewUserRoleAsync(string userId, string roleId);
    Task<ResultDto> RemoveUserRoleAsync(string userId, string roleId);
    #endregion    

    #region Two Factor Authentication
    Task<(string email, string token)> InitiateTwoFactorAuthenticationAsync(ClaimsPrincipal User);
    Task<bool> ConfirmTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim, string authenticatorCode);
    Task<bool> DisableTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim);
    Task<bool> IsTwoFactorEnabled(ClaimsPrincipal principal);
    #endregion

    #region Forgot and change Password
    Task<(string userId, string token)> GeneratePasswordResetTokenAsync(string email);
    Task<ResultDto> ResetPasswordAsync(string email, string token, string newPassword);
    Task<ResultDto> ChangePasswordAsync(ClaimsPrincipal UserClaim, string newPassword);
    #endregion
}
