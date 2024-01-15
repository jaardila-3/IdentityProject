using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Common.Dto;
using IdentityProject.Common.Enums;
using IdentityProject.Common.Mapper.MapperExtensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace IdentityProject.Business.identity;

public class AccountManager(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager) : IAccountManager
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;

    #region Users
    public async Task<(IdentityResult, string)> CreateUserAsync(UserDto user, string password)
    {
        var identityUser = user.ToDomain();
        var identityResult = await _userManager.CreateAsync(identityUser, password);
        return (identityResult, identityUser.Id);
    }

    public async Task<IdentityResult> AddToRoleAsync(IdentityUser user, string role) => await _userManager.AddToRoleAsync(user, role);

    public async Task<IdentityUser?> FindByIdAsync(string userId) => await _userManager.FindByIdAsync(userId);

    public async Task<string> GenerateEmailConfirmationTokenAsync(IdentityUser user) => await _userManager.GenerateEmailConfirmationTokenAsync(user);

    public async Task<IdentityResult> ConfirmEmailAsync(IdentityUser user, string token) => await _userManager.ConfirmEmailAsync(user, token);

    public async Task<IdentityUser?> FindByEmailAsync(string email) => await _userManager.FindByEmailAsync(email);

    public async Task<string> GeneratePasswordResetTokenAsync(IdentityUser user) => await _userManager.GeneratePasswordResetTokenAsync(user);

    public async Task<IdentityResult> ResetPasswordAsync(IdentityUser user, string token, string newPassword) => await _userManager.ResetPasswordAsync(user, token, newPassword);

    public async Task<IdentityUser?> GetUserAsync(ClaimsPrincipal principal) => await _userManager.GetUserAsync(principal);

    public async Task<IdentityResult> ResetAuthenticatorKeyAsync(IdentityUser user) => await _userManager.ResetAuthenticatorKeyAsync(user);

    public async Task<string?> GetAuthenticatorKeyAsync(IdentityUser user) => await _userManager.GetAuthenticatorKeyAsync(user);

    public async Task<bool> VerifyTwoFactorTokenAsync(IdentityUser user, string token) => await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, token);

    public async Task<IdentityResult> SetTwoFactorEnabledAsync(IdentityUser user, bool enabled) => await _userManager.SetTwoFactorEnabledAsync(user, enabled);
    #endregion

    #region SignIn
    public async Task SignInAsync(IdentityUser user, bool isPersistent, string? authenticationMethod = null)
        => await _signInManager.SignInAsync(user, isPersistent: isPersistent);

    public async Task SignOutAsync() => await _signInManager.SignOutAsync();

    public async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        => await _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure: lockoutOnFailure);

    public async Task<IdentityUser?> GetTwoFactorAuthenticationUserAsync() => await _signInManager.GetTwoFactorAuthenticationUserAsync();

    public async Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
        => await _signInManager.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient: rememberClient);
    #endregion

    #region Roles
    public async Task<bool> RoleExistsAsync(string roleName) => await _roleManager.RoleExistsAsync(roleName);

    public async Task<IdentityResult> CreateRoleAsync(IdentityRole role) => await _roleManager.CreateAsync(role);

    public async Task<List<IdentityRole>?> GetRolesListAsync() => await _roleManager.Roles.ToListAsync();
    #endregion

    #region Helpers
    public async Task CreateRolesAsync()
    {
        if (!await RoleExistsAsync(nameof(RoleType.RegisteredUser)))
            await CreateRoleAsync(new IdentityRole(nameof(RoleType.RegisteredUser)));

        if (!await RoleExistsAsync(nameof(RoleType.Admin)))
            await CreateRoleAsync(new IdentityRole(nameof(RoleType.Admin)));
    }
    #endregion
}
