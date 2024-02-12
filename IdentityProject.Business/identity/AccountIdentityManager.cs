using IdentityProject.Business.Exceptions;
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

    #region Register
    public async Task<(ResultDto result, string userId)> CreateUserAsync(UserDto user, string password, string roleName, bool autoSignIn = true)
    {
        var identityUser = user.ToDomain();
        var userCreationResult = await _userManager.CreateAsync(identityUser, password);
        if (userCreationResult is null) return (ResultDto.Failure(["No se pudo crear el usuario"]), string.Empty);
        if (!userCreationResult.Succeeded) return (userCreationResult.ToApplicationResult(), string.Empty);

        if (!await _roleManager.RoleExistsAsync(roleName)) return (ResultDto.Failure(["No existe el rol para el usuario"]), string.Empty);

        var roleAdditionResult = await _userManager.AddToRoleAsync(identityUser, roleName);
        if (!roleAdditionResult.Succeeded)
        {
            //delete user created
            await _userManager.DeleteAsync(identityUser);
            return (ResultDto.Failure(["No se pudo crear el usuario"]), string.Empty);
        }

        if (autoSignIn) await _signInManager.SignInAsync(identityUser, isPersistent: false);
        return (ResultDto.Success(), identityUser.Id);
    }

    public async Task<string> GenerateEmailConfirmationTokenAsync(string userId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId);
        if (identityUser is null) return string.Empty;
        return await _userManager.GenerateEmailConfirmationTokenAsync(identityUser);
    }

    public async Task<bool> ConfirmEmailAsync(string userId, string token)
    {
        var identityUser = await _userManager.FindByIdAsync(userId);
        if (identityUser is null) return false;
        var identityResult = await _userManager.ConfirmEmailAsync(identityUser, token);
        if (identityResult is null) return false;
        return identityResult.Succeeded;
    }
    #endregion

    #region Users
    public async Task<ResultDto> UpdateUserAsync(UserDto userDto)
    {
        var identityUser = (AppUser?)await _userManager.FindByIdAsync(userDto.Id!);
        if (identityUser is null) return ResultDto.Failure(["No existe el usuario"]);
        identityUser.Name = userDto.Name;
        identityUser.Url = userDto.Url;
        identityUser.CountryCode = userDto.CountryCode;
        identityUser.PhoneNumber = userDto.PhoneNumber;
        identityUser.Country = userDto.Country;
        identityUser.City = userDto.City;
        identityUser.Address = userDto.Address;
        identityUser.Birthdate = userDto.Birthdate;
        var identityResult = await _userManager.UpdateAsync(identityUser);
        if (identityResult is null) return ResultDto.Failure(["No se pudo actualizar el usuario"]);
        return identityResult.ToApplicationResult();
    }

    public async Task<ResultDto> LockAndUnlockUserAsync(string id, DateTimeOffset? endDate = null)
    {
        endDate ??= DateTimeOffset.UtcNow;
        var identityUser = await _userManager.FindByIdAsync(id);
        if (identityUser is null) return ResultDto.Failure(["No existe el usuario"]);

        //activate this feature if you want to lock users, if you don't activate it, you can't lock users and the user will be able to login
        //in database is the LockoutEnabled field
        var lockUserResult = await _userManager.SetLockoutEnabledAsync(identityUser, true);
        if (lockUserResult is null) return ResultDto.Failure(["No se pudo activar la funcionalidad de bloqueo de usuario."]);

        var lockDateResult = await _userManager.SetLockoutEndDateAsync(identityUser, endDate);
        if (lockDateResult is null) return ResultDto.Failure(["No se pudo establecer la fecha final para bloquear al usuario."]);

        if (lockUserResult.Succeeded && lockDateResult.Succeeded) return ResultDto.Success();
        return ResultDto.Failure(["Error inesperado al bloquear el usuario."]);
    }

    public async Task<ResultDto> DeleteUserAsync(string id)
    {
        var identityUser = await _userManager.FindByIdAsync(id);
        if (identityUser is null) return ResultDto.Failure(["No existe el usuario"]);

        var identityResult = await _userManager.DeleteAsync(identityUser);
        if (identityResult is null) return ResultDto.Failure(["No se pudo eliminar el usuario"]);
        return identityResult.ToApplicationResult();
    }

    public async Task<IList<Claim>> GetRemoveOrAssignUserClaimsByIdAsync(string id, bool removeClaims = false, IEnumerable<Claim>? assignClaims = null)
    {
        var identityUser = await _userManager.FindByIdAsync(id) ?? throw new UserNotFoundException("El usuario no existe");
        var userClaims = await _userManager.GetClaimsAsync(identityUser) ?? [];
        if (removeClaims && userClaims.Any())
        {
            var identityResult = await _userManager.RemoveClaimsAsync(identityUser, userClaims);
            if (identityResult is null || !identityResult.Succeeded) throw new IdentityUserManagerException("No se pudo remover los permisos del usuario");
            userClaims = [];
        }
        if (assignClaims is not null && assignClaims.Any())
        {
            var identityResult = await _userManager.AddClaimsAsync(identityUser, assignClaims);
            if (identityResult is null || !identityResult.Succeeded) throw new IdentityUserManagerException("No se pudo asignar los permisos del usuario");
            userClaims = await _userManager.GetClaimsAsync(identityUser) ?? [];
        }
        return userClaims;
    }
    #endregion

    #region SignIn    
    public async Task SignOutAsync() => await _signInManager.SignOutAsync();

    public async Task<ResultDto> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
    {
        var authenticationResult = await _signInManager.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure: lockoutOnFailure);
        if (authenticationResult is null) return ResultDto.Failure(["Error inesperado al iniciar sesión."]);
        return authenticationResult.ToApplicationResult();
    }

    public async Task GetTwoFactorAuthenticationUserAsync()
    {
        if (await _signInManager.GetTwoFactorAuthenticationUserAsync() is null)
            throw new IdentitySignInManagerException("El usuario no tiene dos factores de autenticación activado");
    }

    public async Task<ResultDto> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient)
    {
        var signInResult = await _signInManager.TwoFactorAuthenticatorSignInAsync(code, isPersistent, rememberClient: rememberClient);
        if (signInResult is null) return ResultDto.Failure(["No se pudo validar el código de verificación."]);
        return signInResult.ToApplicationResult();
    }
    #endregion

    #region Roles
    public async Task<ResultDto> CreateRoleAsync(string roleName)
    {
        if (await _roleManager.RoleExistsAsync(roleName)) return ResultDto.Failure([$"El rol: {roleName}, ya existe en el sistema"]);
        var identityResult = await _roleManager.CreateAsync(new IdentityRole(roleName));
        if (identityResult is null) return ResultDto.Failure(["No se pudo crear el rol"]);
        return identityResult.ToApplicationResult();
    }

    public async Task<ResultDto> UpdateRoleAsync(RoleDto roleDto)
    {
        var identityRole = await _roleManager.FindByIdAsync(roleDto.Id!);
        if (identityRole is null) return ResultDto.Failure(["El rol No existe en el sistema"]);
        if (await _roleManager.RoleExistsAsync(roleDto.Name!)) return ResultDto.Failure([$"El nombre del rol: {roleDto.Name}, ya existe en el sistema"]);
        //asign the new name
        identityRole.Name = roleDto.Name;
        var identityResult = await _roleManager.UpdateAsync(identityRole);
        if (identityResult is null) return ResultDto.Failure(["No se pudo actualizar el rol"]);
        return identityResult.ToApplicationResult();
    }

    public async Task<List<string?>?> GetRolesAsync() => await _roleManager.Roles.Select(role => role.Name).ToListAsync() ?? [];

    public async Task SetupRolesAsync()
    {
        await CreateRoleAsync(RoleTypeString.RegisteredUser);
        await CreateRoleAsync(RoleTypeString.Administrator);
    }

    public async Task<ResultDto> DeleteRoleAsync(string id)
    {
        var identityRole = await _roleManager.FindByIdAsync(id);
        if (identityRole is null) return ResultDto.Failure(["El rol No existe en el sistema"]);

        // Verify that the role has users assigned
        var usersInRole = await _userManager.GetUsersInRoleAsync(identityRole.Name!);
        if (usersInRole.Any()) return ResultDto.Failure(["El rol tiene usuarios asignados. No se puede eliminar"]);

        var identityResult = await _roleManager.DeleteAsync(identityRole);
        if (identityResult is null) return ResultDto.Failure(["No se pudo eliminar el rol"]);
        return identityResult.ToApplicationResult();
    }

    public async Task<ResultDto> RemoveUserRoleAndAssignNewRoleAsync(string userId, string oldRoleId, string newRoleId)
    {
        var identityUser = await _userManager.FindByIdAsync(userId);
        if (identityUser is null) return ResultDto.Failure(["El usuario No existe en el sistema"]);

        var identityOldRole = await _roleManager.FindByIdAsync(oldRoleId);
        if (identityOldRole is null) return ResultDto.Failure(["El rol No existe en el sistema"]);

        var roleToRemoveResult = await _userManager.RemoveFromRoleAsync(identityUser, identityOldRole.Name!);
        if (roleToRemoveResult is null || !roleToRemoveResult.Succeeded) return ResultDto.Failure(["No se pudo eliminar el rol del usuario"]);

        var identityNewRole = await _roleManager.FindByIdAsync(newRoleId);
        if (identityNewRole is null) return ResultDto.Failure(["El rol No existe en el sistema"]);
        var roleAdditionResult = await _userManager.AddToRoleAsync(identityUser, identityNewRole.Name!);
        if (roleAdditionResult is null) return ResultDto.Failure(["No fue posible asignar el nuevo rol al usuario"]);

        return roleToRemoveResult.ToApplicationResult();
    }
    #endregion

    #region Two Factor Authentication
    public async Task<(string email, string token)> InitiateTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim)
    {
        if (UserClaim is null || !UserClaim.Identity!.IsAuthenticated) return (string.Empty, string.Empty);

        var identityUser = await _userManager.GetUserAsync(UserClaim);
        if (identityUser is null) return (string.Empty, string.Empty);

        var resetAuthenticatorKeyResult = await _userManager.ResetAuthenticatorKeyAsync(identityUser);
        if (resetAuthenticatorKeyResult is null || !resetAuthenticatorKeyResult.Succeeded) return (identityUser.Email!, string.Empty);

        string? token = await _userManager.GetAuthenticatorKeyAsync(identityUser);
        if (token is null) return (identityUser.Email!, string.Empty);

        return (identityUser.Email!, token);
    }

    public async Task<bool> ConfirmTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim, string authenticatorCode)
    {
        if (UserClaim is null || !UserClaim.Identity!.IsAuthenticated) return false;

        var identityUser = await _userManager.GetUserAsync(UserClaim);
        if (identityUser is null) return false;

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

    public async Task<bool> DisableTwoFactorAuthenticationAsync(ClaimsPrincipal UserClaim)
    {
        if (UserClaim is null || !UserClaim.Identity!.IsAuthenticated) return false;

        var identityUser = await _userManager.GetUserAsync(UserClaim) ?? throw new UserNotFoundException("El usuario no existe");

        // Verify two factor authentication is enabled
        if (!await _userManager.GetTwoFactorEnabledAsync(identityUser)) return false;

        // Reset the authenticator key for enhanced security when disabling two-factor authentication.
        var resetAuthenticatorKeyResult = await _userManager.ResetAuthenticatorKeyAsync(identityUser);
        if (resetAuthenticatorKeyResult is null || !resetAuthenticatorKeyResult.Succeeded) return false;

        //Disable two factor authentication
        bool enabled = false;
        var twoFactorDisableResult = await _userManager.SetTwoFactorEnabledAsync(identityUser, enabled);
        if (twoFactorDisableResult is null) return false;

        return twoFactorDisableResult.Succeeded;
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
            ?? throw new IdentityUserManagerException("No se pudo generar el token de restablecimiento de la contraseña");

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
        if (UserClaim is null || !UserClaim.Identity!.IsAuthenticated)
            return ResultDto.Failure(["El usuario no existe o no se ha logueado"]);

        var identityUser = await _userManager.GetUserAsync(UserClaim);
        if (identityUser is null) return ResultDto.Failure(["El usuario no existe"]);

        var token = await _userManager.GeneratePasswordResetTokenAsync(identityUser);
        if (token is null) return ResultDto.Failure(["No se pudo generar el token de restablecimiento de la contraseña"]);

        var resetPasswordResult = await _userManager.ResetPasswordAsync(identityUser, token, newPassword);
        if (resetPasswordResult is null) return ResultDto.Failure(["La contraseña no se pudo restablecer"]);

        return resetPasswordResult.ToApplicationResult();
    }
    #endregion    
}
