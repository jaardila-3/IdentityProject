using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Common.Dto;
using IdentityProject.Common.Enums;
using IdentityProject.Common.Mapper.MapperExtensions;
using IdentityProject.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace IdentityProject.Business.identity;

public class AccountIdentityManager(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager) : IAccountIdentityManager
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;

    #region Users
    public async Task<(ResultDto result, string userId)> CreateUserAsync(UserDto user, string password)
    {
        var identityUser = user.ToDomain();
        var identityResult = await _userManager.CreateAsync(identityUser, password);
        return (identityResult.ToApplicationResult(), identityUser.Id);
    }

    public async Task<ResultDto> AddUserToRoleAsync(string userId, string role)
    {
        if (!await _roleManager.RoleExistsAsync(role))
            throw new InvalidOperationException("El rol no existe");

        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        var identityResult = await _userManager.AddToRoleAsync(identityUser, role);
        return identityResult.ToApplicationResult();
    }

    public async Task<string> GenerateEmailConfirmationTokenAsync(string userId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        return await _userManager.GenerateEmailConfirmationTokenAsync(identityUser);
    }

    public async Task<ResultDto> ConfirmEmailAsync(string userId, string token)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        var identityResult = await _userManager.ConfirmEmailAsync(identityUser, token);
        return identityResult.ToApplicationResult();
    }

    public async Task<string?> FindByEmailAsync(string email)
    {
        var identityUser = await _userManager.FindByEmailAsync(email);
        return identityUser?.Id;
    }

    public async Task<string> GeneratePasswordResetTokenAsync(string userId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        return await _userManager.GeneratePasswordResetTokenAsync(identityUser);
    }

    public async Task<ResultDto> ResetPasswordAsync(string userId, string token, string newPassword)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        var identityResult = await _userManager.ResetPasswordAsync(identityUser, token, newPassword);
        return identityResult.ToApplicationResult();
    }

    public async Task<string?> GetUserAsync(ClaimsPrincipal principal)
    {
        var identityUser = await _userManager.GetUserAsync(principal);
        return identityUser?.Id;
    }

    public async Task<bool> IsTwoFactorEnabled(ClaimsPrincipal principal)
    {
        bool isTwoFactorEnabled = false;
        var identityUser = await _userManager.GetUserAsync(principal);
        if (identityUser is not null) isTwoFactorEnabled = identityUser.TwoFactorEnabled;
        return isTwoFactorEnabled;
    }

    public async Task<ResultDto> ResetAuthenticatorKeyAsync(string userId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        var identityResult = await _userManager.ResetAuthenticatorKeyAsync(identityUser);
        return identityResult.ToApplicationResult();
    }

    public async Task<string?> GetAuthenticatorKeyAsync(string userId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        return await _userManager.GetAuthenticatorKeyAsync(identityUser);
    }

    public async Task<bool> VerifyTwoFactorTokenAsync(string userId, string token)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        return await _userManager.VerifyTwoFactorTokenAsync(identityUser, _userManager.Options.Tokens.AuthenticatorTokenProvider, token);
    }

    public async Task<ResultDto> SetTwoFactorEnabledAsync(string userId, bool enabled)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        var identityResult = await _userManager.SetTwoFactorEnabledAsync(identityUser, enabled);
        return identityResult.ToApplicationResult();
    }

    public async Task<ResultDto> UpdateUserAsync(UserDto userDto)
    {
        var identityUser = (AppUser?)await _userManager.FindByIdAsync(userDto.Id!) ?? throw new InvalidOperationException("El usuario no existe");
        identityUser.Name = userDto.Name;
        identityUser.Url = userDto.Url;
        identityUser.CountryCode = userDto.CountryCode;
        identityUser.PhoneNumber = userDto.PhoneNumber;
        identityUser.Country = userDto.Country;
        identityUser.City = userDto.City;
        identityUser.Address = userDto.Address;
        identityUser.Birthdate = userDto.Birthdate;
        var identityResult = await _userManager.UpdateAsync(identityUser);
        return identityResult.ToApplicationResult();
    }

    public async Task DeleteUserAsync(string userId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        var identityResult = await _userManager.DeleteAsync(identityUser);
        if (!identityResult.Succeeded) throw new InvalidOperationException("Usuario no pudo ser eliminado.");
    }
    #endregion

    #region SignIn
    public async Task SignInAsync(string userId, bool isPersistent, string? authenticationMethod = null)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new InvalidOperationException("Usuario no encontrado.");
        await _signInManager.SignInAsync(identityUser, isPersistent: isPersistent);
    }

    public async Task SignOutAsync() => await _signInManager.SignOutAsync();

    public async Task<ResultDto> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        var signInResult = await _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure: lockoutOnFailure)
            ?? throw new InvalidOperationException("Credenciales incorrectas");
        return signInResult.ToApplicationResult();
    }

    public async Task GetTwoFactorAuthenticationUserAsync()
    {
        if (await _signInManager.GetTwoFactorAuthenticationUserAsync() is null)
            throw new InvalidOperationException("El usuario no tiene dos factores de autenticación activado");
    }

    public async Task<ResultDto> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
    {
        var signInResult = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient: rememberClient)
            ?? throw new InvalidOperationException("No se pudo validar el código de verificación.");
        return signInResult.ToApplicationResult();
    }
    #endregion

    #region Roles
    public async Task<bool> RoleExistsAsync(string roleName) => await _roleManager.RoleExistsAsync(roleName);

    public async Task<ResultDto> CreateRoleAsync(IdentityRole role)
    {
        var identityResult = await _roleManager.CreateAsync(role);
        return identityResult.ToApplicationResult();
    }

    public async Task<List<string?>?> GetRolesAsync() => await _roleManager.Roles.Select(role => role.Name).ToListAsync() ?? [];

    #endregion

    #region Helpers
    public async Task CreateRolesAsync()
    {
        if (!await _roleManager.RoleExistsAsync(nameof(RoleType.RegisteredUser)))
            await CreateRoleAsync(new IdentityRole(nameof(RoleType.RegisteredUser)));

        if (!await _roleManager.RoleExistsAsync(nameof(RoleType.Admin)))
            await CreateRoleAsync(new IdentityRole(nameof(RoleType.Admin)));
    }
    #endregion
}
