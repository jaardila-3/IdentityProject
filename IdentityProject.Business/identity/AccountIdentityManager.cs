using IdentityProject.Business.Exceptions;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Common.Dto;
using IdentityProject.Common.Enums;
using IdentityProject.Common.Mapper.MapperExtensions;
using IdentityProject.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.Json;

namespace IdentityProject.Business.identity;

public class AccountIdentityManager(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager) : IAccountIdentityManager
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;

    #region Register
    public async Task<(ResultDto result, string userId)> CreateUserAsync(UserDto user, string password, string roleName, bool autoSignIn = true)
    {
        var identityUser = user.ToDomain();
        var userCreationResult = await _userManager.CreateAsync(identityUser, password);
        if (!userCreationResult.Succeeded) return (userCreationResult.ToApplicationResult(), string.Empty);

        if (!await _roleManager.RoleExistsAsync(roleName)) throw new RoleNotFoundException("El rol no existe");

        var roleAdditionResult = await _userManager.AddToRoleAsync(identityUser, roleName);
        if (!roleAdditionResult.Succeeded)
        {
            //delete user created
            await _userManager.DeleteAsync(identityUser);
            throw new UserRoleAssignmentFailedException($"Error al asignar el rol al usuario. userId: {identityUser.Id}");
        }

        if (autoSignIn) await _signInManager.SignInAsync(identityUser, isPersistent: false);
        return (ResultDto.Success(), identityUser.Id);
    }

    public async Task<string> GenerateEmailConfirmationTokenAsync(string userId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new UserNotFoundException("Usuario no encontrado.");
        return await _userManager.GenerateEmailConfirmationTokenAsync(identityUser);
    }

    public async Task ConfirmEmailAsync(string userId, string token)
    {
        var identityUser = await _userManager.FindByIdAsync(userId) ?? throw new UserNotFoundException("Usuario no encontrado.");
        var identityResult = await _userManager.ConfirmEmailAsync(identityUser, token);
        if (!identityResult.Succeeded) throw new EmailConfirmationFailedException("Error al confirmar el correo: " + JsonSerializer.Serialize(identityResult.Errors));
    }
    #endregion

    #region Users
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
    #endregion

    #region SignIn    
    public async Task SignOutAsync() => await _signInManager.SignOutAsync();

    public async Task<ResultDto> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        var authenticationResult = await _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure: lockoutOnFailure)
            ?? throw new AuthenticationFailedException("Error inesperado al iniciar sesión.");
        return authenticationResult.ToApplicationResult();
    }

    public async Task GetTwoFactorAuthenticationUserAsync()
    {
        if (await _signInManager.GetTwoFactorAuthenticationUserAsync() is null)
            throw new AuthenticationFailedException("El usuario no tiene dos factores de autenticación activado");
    }

    public async Task<ResultDto> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
    {
        var signInResult = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient: rememberClient)
            ?? throw new AuthenticationFailedException("No se pudo validar el código de verificación.");
        return signInResult.ToApplicationResult();
    }
    #endregion

    #region Roles
    public async Task<ResultDto> CreateRoleAsync(string roleName)
    {
        if (await _roleManager.RoleExistsAsync(roleName))
        {
            return ResultDto.Failure([$"El rol: {roleName}, ya existe en el sistema"]);
        }
        var identityResult = await _roleManager.CreateAsync(new IdentityRole(roleName));
        return identityResult.ToApplicationResult();
    }

    public async Task<List<string?>?> GetRolesAsync() => await _roleManager.Roles.Select(role => role.Name).ToListAsync() ?? [];

    public async Task SetupRolesAsync()
    {
        await CreateRoleAsync(nameof(RoleType.Usuario_Registrado));
        await CreateRoleAsync(nameof(RoleType.Admin));
    }
    #endregion

    #region Two Factor Authentication
    public async Task<(string token, string email)> InitiateTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim)
    {
        if (UserClaim is null || !UserClaim.Identity!.IsAuthenticated)
            throw new ArgumentNullException(nameof(UserClaim));

        var identityUser = await _userManager.GetUserAsync(UserClaim) ?? throw new UserNotFoundException("El usuario no existe");
        var resetAuthenticatorKeyResult = await _userManager.ResetAuthenticatorKeyAsync(identityUser);
        if (!resetAuthenticatorKeyResult.Succeeded) throw new AuthenticationFailedException("No se pudo restablecer la clave de autenticación");
        string token = await _userManager.GetAuthenticatorKeyAsync(identityUser) ?? throw new AuthenticationFailedException("La clave de autenticación no existe");
        return (token, identityUser.Email!);
    }

    public async Task<bool> ConfirmTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim, string authenticatorCode)
    {
        if (UserClaim is null || !UserClaim.Identity!.IsAuthenticated)
            throw new ArgumentNullException(nameof(UserClaim));

        var identityUser = await _userManager.GetUserAsync(UserClaim) ?? throw new UserNotFoundException("El usuario no existe");
        //verify token is valid
        bool isSucceeded = await _userManager.VerifyTwoFactorTokenAsync(identityUser, _userManager.Options.Tokens.AuthenticatorTokenProvider, authenticatorCode);
        if (isSucceeded)
        {
            //activate two factor authentication
            bool enabled = true;
            var identityResult = await _userManager.SetTwoFactorEnabledAsync(identityUser, enabled);
            return identityResult.Succeeded;
        }
        return isSucceeded; //false
    }

    public async Task DisableTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim)
    {
        if (UserClaim is null || !UserClaim.Identity!.IsAuthenticated)
            throw new ArgumentNullException(nameof(UserClaim));

        var identityUser = await _userManager.GetUserAsync(UserClaim) ?? throw new UserNotFoundException("El usuario no existe");
        // Verify two factor authentication is enabled
        if (!await _userManager.GetTwoFactorEnabledAsync(identityUser))
            throw new InvalidOperationException("La autenticación de dos factores no está habilitada para este usuario");

        //Disable two factor authentication
        var resultResetAuthenticatorKey = await _userManager.ResetAuthenticatorKeyAsync(identityUser);
        bool enabled = false;
        var resultTwoFactorDisable = await _userManager.SetTwoFactorEnabledAsync(identityUser, enabled);
        if (!resultResetAuthenticatorKey.Succeeded || !resultTwoFactorDisable.Succeeded)
            throw new AuthenticationFailedException("No se pudo deshabilitar la autenticación de dos factores.");
    }

    public async Task<bool> IsTwoFactorEnabled(ClaimsPrincipal UserClaim)
    {
        bool isTwoFactorEnabled = false;
        var identityUser = await _userManager.GetUserAsync(UserClaim);
        if (identityUser is not null) isTwoFactorEnabled = identityUser.TwoFactorEnabled;
        return isTwoFactorEnabled;
    }
    #endregion

    #region Forgot and change Password
    public async Task<(string userId, string token)> GeneratePasswordResetTokenAsync(string email)
    {
        var identityUser = await _userManager.FindByEmailAsync(email);
        if (identityUser is null) return (string.Empty, string.Empty);

        var token = await _userManager.GeneratePasswordResetTokenAsync(identityUser)
            ?? throw new TokenGenerationFailedException("No se pudo generar el token de restablecimiento de la contraseña");

        return (identityUser.Id, token);
    }

    public async Task<ResultDto> ResetPasswordAsync(string email, string token, string newPassword)
    {
        var identityUser = await _userManager.FindByEmailAsync(email);
        if (identityUser is null) return ResultDto.Failure(["El usuario no existe"]);

        var resetPasswordResult = await _userManager.ResetPasswordAsync(identityUser, token, newPassword);
        if (resetPasswordResult is null) return ResultDto.Failure(["La contraseña no se pudo restablecer"]);
        return resetPasswordResult.ToApplicationResult();
    }

    public async Task<ResultDto> ChangePasswordAsync(ClaimsPrincipal UserClaim, string newPassword)
    {
        var identityUser = await _userManager.GetUserAsync(UserClaim) ?? throw new UserNotFoundException("El usuario no existe");
        var token = await _userManager.GeneratePasswordResetTokenAsync(identityUser) ?? throw new TokenGenerationFailedException("No se pudo generar el token de restablecimiento de la contraseña");
        var resetPasswordResult = await _userManager.ResetPasswordAsync(identityUser, token, newPassword);
        return resetPasswordResult.ToApplicationResult();
    }
    #endregion    
}
