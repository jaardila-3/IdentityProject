using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Common.Enums;
using IdentityProject.Domain.Entities;
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
    public async Task<IdentityResult> CreateUserAsync(AppUser user, string password)
    {
        return await _userManager.CreateAsync(user, password);
    }

    public async Task<IdentityResult> AddToRoleAsync(AppUser user, string role)
    {
        return await _userManager.AddToRoleAsync(user, role);
    }

    public async Task<IdentityUser?> FindByIdAsync(string userId)
    {
        return await _userManager.FindByIdAsync(userId);
    }

    public async Task<IdentityResult> ConfirmEmailAsync(IdentityUser user, string token)
    {
        return await _userManager.ConfirmEmailAsync(user, token);
    }

    public async Task<IdentityUser?> FindByEmailAsync(string email)
    {
        return await _userManager.FindByEmailAsync(email);
    }

    public async Task<string> GeneratePasswordResetTokenAsync(IdentityUser user)
    {
        return await _userManager.GeneratePasswordResetTokenAsync(user);
    }

    public async Task<IdentityResult> ResetPasswordAsync(IdentityUser user, string token, string newPassword)
    {
        return await _userManager.ResetPasswordAsync(user, token, newPassword);
    }

    public async Task<string> GenerateEmailConfirmationTokenAsync(AppUser user)
    {
        return await _userManager.GenerateEmailConfirmationTokenAsync(user);
    }

    public async Task<IdentityUser?> GetUserAsync(ClaimsPrincipal principal)
    {
        return await _userManager.GetUserAsync(principal);
    }

    public async Task<IdentityResult> ResetAuthenticatorKeyAsync(IdentityUser user)
    {
        return await _userManager.ResetAuthenticatorKeyAsync(user);
    }

    public async Task<string?> GetAuthenticatorKeyAsync(IdentityUser user)
    {
        return await _userManager.GetAuthenticatorKeyAsync(user);
    }

    public async Task<bool> VerifyTwoFactorTokenAsync(IdentityUser user, string token)
    {
        return await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, token);
    }

    public async Task<IdentityResult> SetTwoFactorEnabledAsync(IdentityUser user, bool enabled)
    {
        return await _userManager.SetTwoFactorEnabledAsync(user, enabled);
    }
    #endregion

    #region SignIn
    public async Task SignInAsync(AppUser user, bool isPersistent, string? authenticationMethod = null)
    {
        await _signInManager.SignInAsync(user, isPersistent: isPersistent);
    }

    public async Task SignOutAsync()
    {
        await _signInManager.SignOutAsync();
    }

    public async Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        return await _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure: lockoutOnFailure);
    }

    public async Task<IdentityUser?> GetTwoFactorAuthenticationUserAsync()
    {
        return await _signInManager.GetTwoFactorAuthenticationUserAsync();
    }

    public async Task<SignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
    {
        return await _signInManager.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient: rememberClient);
    }
    #endregion

    #region Roles
    public async Task<bool> RoleExistsAsync(string roleName)
    {
        return await _roleManager.RoleExistsAsync(roleName);
    }

    public async Task<IdentityResult> CreateRoleAsync(IdentityRole role)
    {
        return await _roleManager.CreateAsync(role);
    }

    public async Task<List<IdentityRole>?> GetRolesListAsync()
    {
        return await _roleManager.Roles.ToListAsync();
    }
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
