using IdentityProject.Web.Models;
using IdentityProject.Web.Models.MapperExtensions;
using IdentityProject.Web.Interfaces.Controllers;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Email;
using IdentityProject.Common.Enums;
using IdentityProject.Common.ExtensionMethods;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Authorization;
using System.Text.Encodings.Web;
using System.Text.Json;
using IdentityProject.Common.Dto;

namespace IdentityProject.Web.Controllers;

[Authorize]
public class AccountController(IErrorController errorController, IAccountIdentityManager accountIdentityManager, IEmailService emailService, UrlEncoder urlEncoder) : Controller
{
    private readonly IErrorController _errorController = errorController;
    private readonly IAccountIdentityManager _accountIdentityManager = accountIdentityManager;
    private readonly IEmailService _emailService = emailService;
    private readonly UrlEncoder _urlEncoder = urlEncoder;

    #region Register
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Register()
    {
        try
        {
            await _accountIdentityManager.CreateRolesAsync();
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(Register), "Error al crear roles");
        }
        RegisterViewModel model = new();
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            try
            {
                viewModel.State = true;
                var userToCreateDto = viewModel.ToDto();
                var (resultDtoUsercreated, userId) = await _accountIdentityManager.CreateUserAsync(userToCreateDto, viewModel.Password!);

                if (resultDtoUsercreated.Succeeded)
                {
                    var resultDtoRoleAdded = await _accountIdentityManager.AddUserToRoleAsync(userId, nameof(RoleType.RegisteredUser));
                    if (resultDtoRoleAdded.Succeeded)
                    {
                        await SendEmailConfirmationRegisterAsync(userId, viewModel.Email!);
                        await _accountIdentityManager.SignInAsync(userId, false);
                        return RedirectToAction(nameof(HomeController.Index), "Home");
                    }
                    await _accountIdentityManager.DeleteUserAsync(userId);
                    _errorController.HandleErrors(resultDtoRoleAdded.Errors);
                }
                else
                    _errorController.HandleErrors(resultDtoUsercreated.Errors);
            }
            catch (Exception ex)
            {
                return _errorController.HandleException(ex, nameof(Register));
            }
        }
        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> RegisterAdmin()
    {
        try
        {
            // await _identityManager.CreateRolesAsync();
            RegisterViewModel viewModel = new() { Roles = await GetRoleItemsAsync() };
            return View(viewModel);
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(RegisterAdmin));
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterAdmin(RegisterViewModel viewModel)
    {
        if (!ModelState.IsValid)
        {
            viewModel.Roles = await GetRoleItemsAsync();
            return View(viewModel);
        }
        if (string.IsNullOrEmpty(viewModel.SelectedRole))
        {
            ModelState.AddModelError(string.Empty, "Debe seleccionar un rol");
            viewModel.Roles = await GetRoleItemsAsync();
            return View(viewModel);
        }

        try
        {
            viewModel.State = true;
            var userToCreateDto = viewModel.ToDto();
            var (resultDtoUsercreated, userId) = await _accountIdentityManager.CreateUserAsync(userToCreateDto, viewModel.Password!);

            if (resultDtoUsercreated.Succeeded)
            {
                var resultDtoRoleAdded = await _accountIdentityManager.AddUserToRoleAsync(userId, viewModel.SelectedRole);
                if (resultDtoRoleAdded.Succeeded)
                {
                    await SendEmailConfirmationRegisterAsync(userId, viewModel.Email!);
                    return RedirectToAction(nameof(HomeController.Index), "Home");
                }
                await _accountIdentityManager.DeleteUserAsync(userId);
                _errorController.HandleErrors(resultDtoRoleAdded.Errors);
            }
            else
                _errorController.HandleErrors(resultDtoUsercreated.Errors);
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(RegisterAdmin));
        }
        viewModel.Roles = await GetRoleItemsAsync();
        return View(viewModel);
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
        try
        {
            var resultDto = await _accountIdentityManager.ConfirmEmailAsync(userId, code ?? throw new ArgumentNullException(nameof(code)));
            if (!resultDto.Succeeded)
                throw new InvalidOperationException($"Error al confirmar el correo: {JsonSerializer.Serialize(resultDto.Errors)}");

            return View(nameof(ConfirmEmail));
        }
        catch (ArgumentNullException ex)
        {
            return _errorController.HandleException(ex, nameof(ConfirmEmail), "Parámetro nulo");
        }
        catch (InvalidOperationException ex)
        {
            return _errorController.HandleException(ex, nameof(ConfirmEmail), "Error en el proceso de confirmar el correo o el usuario");
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(ConfirmEmail));
        }
    }
    #endregion

    #region Login
    [HttpGet]
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginViewModel viewModel, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        returnUrl ??= Url.Content("~/");
        ResultDto signInResultDto;

        if (ModelState.IsValid)
        {
            try
            {
                signInResultDto = await _accountIdentityManager.PasswordSignInAsync(viewModel.UserName!, viewModel.Password!, viewModel.RememberMe, true);
            }
            catch (Exception ex)
            {
                return _errorController.HandleException(ex, nameof(Login));
            }

            if (signInResultDto.Succeeded)
                return LocalRedirect(returnUrl);

            else if (signInResultDto.IsLockedOut || signInResultDto.IsNotAllowed)
                return View("AccountLocked");

            #region Two Factor Authentication
            else if (signInResultDto.RequiresTwoFactor)
                return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnUrl, viewModel.RememberMe });
            #endregion
            else
            {
                ModelState.AddModelError(string.Empty, "Acceso inválido.");
                return View(viewModel);
            }
        }
        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        try
        {
            await _accountIdentityManager.SignOutAsync();
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(Logout));
        }
        return RedirectToAction(nameof(HomeController.Index), "Home");
    }
    #endregion

    #region Forgot Password
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            try
            {
                var userId = await _accountIdentityManager.FindByEmailAsync(viewModel.Email!);
                if (userId is null)
                {
                    ModelState.AddModelError(string.Empty, "El correo no se encuentra registrado.");
                    return View(viewModel);
                }
                var code = await _accountIdentityManager.GeneratePasswordResetTokenAsync(userId);
                var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { userId, code }, protocol: HttpContext.Request.Scheme);

                var subject = "Recuperar contraseña - IdentityProject";
                var bodyHtml = @$"<p>Estimado usuario,</p>
                <p>Hemos recibido una solicitud para restablecer la contraseña de su cuenta en IdentityProject. Si usted hizo esta solicitud, puede seguir el siguiente enlace para crear una nueva contraseña:</p>
                <p><a href='{callbackUrl}'>Restablecer contraseña</a></p>
                <p>Este enlace es válido por 24 horas. Si no lo usa dentro de ese plazo, deberá solicitar otro cambio de contraseña.</p>
                <p>Si usted no hizo esta solicitud, puede ignorar este correo. Su contraseña actual no se verá afectada.</p>
                <p>Gracias por usar IdentityProject.</p>
                <p>Atentamente,</p>
                <p>El equipo de IdentityProject</p>";

                await _emailService.SendEmailAsync(viewModel.Email!, subject, bodyHtml);
            }
            catch (Exception ex)
            {
                return _errorController.HandleException(ex, nameof(ForgotPassword));
            }
            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }
        return View(viewModel);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation() => View();

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string? code = null)
    {
        try
        {
            return code is null ? throw new ArgumentNullException(nameof(code)) : View();
        }
        catch (ArgumentNullException ex)
        {
            return _errorController.HandleException(ex, nameof(ResetPassword), "código nulo");
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            try
            {
                var identityUser = await _accountIdentityManager.FindByEmailAsync(viewModel.Email!);
                if (identityUser is null)
                {
                    ModelState.AddModelError(string.Empty, "El correo no se encuentra registrado.");
                    return View(viewModel);
                }

                var identityResult = await _accountIdentityManager.ResetPasswordAsync(identityUser, viewModel.Code!, viewModel.Password!);
                if (identityResult.Succeeded)
                    return RedirectToAction(nameof(ResetPasswordConfirmation));

                _errorController.HandleErrors(identityResult);
            }
            catch (Exception ex)
            {
                return _errorController.HandleException(ex, nameof(ResetPassword));
            }
        }
        return View(viewModel);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation() => View();
    #endregion

    #region Helpers
    private async Task<List<SelectListItem>> GetRoleItemsAsync()
    {
        var roles = await _accountIdentityManager.GetRolesAsync() ?? [];
        List<SelectListItem> roleItems = [];

        foreach (var role in roles)
        {
            if (Enum.TryParse<RoleType>(role, out var roleType))
            {
                roleItems.Add(new SelectListItem()
                {
                    Value = roleType.ToString(),
                    Text = roleType.DisplayName()
                });
            }
        }
        return roleItems;
    }

    private async Task SendEmailConfirmationRegisterAsync(string userId, string email)
    {
        var token = await _accountIdentityManager.GenerateEmailConfirmationTokenAsync(userId);
        var callbackUrl = Url.Action(nameof(ConfirmEmail), "Account", new { userId, code = token }, protocol: HttpContext.Request.Scheme);
        var subject = "Confirmar su cuenta de IdentityProject";
        var bodyHtml = @$"<p>Hola,</p>
                    <p>Usted ha sido registrado en IdentityProject. Estamos encantados de tenerle como usuario.</p>
                    <p>Para completar su registro y acceder a todas las funcionalidades de la aplicación, solo tiene que hacer clic en el siguiente enlace:</p>
                    <p><a href='{callbackUrl}'>Confirmar cuenta</a></p>
                    <p>Este enlace es válido por 24 horas. Si no lo usa dentro de ese plazo, deberá registrarse de nuevo.</p> 
                    <p>Si tiene alguna duda o problema, puede contactarnos en (email de soporte).</p>
                    <p>¡Esperamos que disfrute de IdentityProject!</p>
                    <p>Saludos,</p>
                    <p>El equipo de IdentityProject</p>";
        await _emailService.SendEmailAsync(email, subject, bodyHtml);
    }
    #endregion

    #region AccessDenied
    [HttpGet]
    [AllowAnonymous]
    public IActionResult AccessDenied() => View();
    #endregion

    #region Two Factor Authentication
    [HttpGet]
    public async Task<IActionResult> ActivateTwoFactorAuthentication()
    {
        try
        {
            var identityUser = await _accountIdentityManager.GetUserAsync(User) ?? throw new InvalidOperationException("El usuario no existe");
            var identityResult = await _accountIdentityManager.ResetAuthenticatorKeyAsync(identityUser);
            if (!identityResult.Succeeded)
                throw new InvalidOperationException("No se pudo restablecer la clave de autenticación");

            string? token = await _accountIdentityManager.GetAuthenticatorKeyAsync(identityUser) ?? throw new InvalidOperationException("La clave de autenticación no existe");
            // Create QR code
            string authenticatorUrlFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            string authenticatorUrl = string.Format(authenticatorUrlFormat, _urlEncoder.Encode("IdentityProject"), _urlEncoder.Encode(identityUser.Email!), token);

            var viewModel = new TwoFactorAuthenticationViewModel() { Token = token, QrCodeUri = authenticatorUrl };
            return View(viewModel);
        }
        catch (InvalidOperationException ex)
        {
            return _errorController.HandleException(ex, nameof(ActivateTwoFactorAuthentication), "Error con la autenticación del usuario.");
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(ActivateTwoFactorAuthentication));
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ActivateTwoFactorAuthentication(TwoFactorAuthenticationViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            try
            {
                var identityUser = await _accountIdentityManager.GetUserAsync(User) ?? throw new InvalidOperationException("El usuario no existe");

                bool isSucceeded = await _accountIdentityManager.VerifyTwoFactorTokenAsync(identityUser, viewModel.Code!);
                if (isSucceeded)
                {
                    var identityResult = await _accountIdentityManager.SetTwoFactorEnabledAsync(identityUser, true);
                    if (!identityResult.Succeeded)
                        throw new InvalidOperationException("No se pudo habilitar la autenticación de dos factores");

                    return RedirectToAction(nameof(AuthenticatorConfirmation));
                }
            }
            catch (InvalidOperationException ex)
            {
                return _errorController.HandleException(ex, nameof(ActivateTwoFactorAuthentication), "usuario no encontrado");
            }
            catch (Exception ex)
            {
                return _errorController.HandleException(ex, nameof(ActivateTwoFactorAuthentication));
            }

            ModelState.AddModelError(string.Empty, "La autenticación de dos factores no ha sido validada correctamente.");
            return View(viewModel);
        }
        return View(viewModel);
    }

    [HttpGet]
    public IActionResult AuthenticatorConfirmation() => View();

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        ViewData["ReturnUrl"] = returnUrl;
        try
        {
            // Gets the user who is in the process of two-factor authentication. If the user does not exist, an exception is thrown.
            var identityUser = await _accountIdentityManager.GetTwoFactorAuthenticationUserAsync()
                ?? throw new InvalidOperationException("El usuario no está en proceso de autenticación de dos factores.");
        }
        catch (InvalidOperationException ex)
        {
            return _errorController.HandleException(ex, nameof(VerifyAuthenticatorCode), "El usuario no está en proceso de autenticación de dos factores.");
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(VerifyAuthenticatorCode));
        }
        return View(new VerifyAuthenticatorCodeViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorCodeViewModel viewModel)
    {
        viewModel.ReturnUrl ??= Url.Content("~/");
        Microsoft.AspNetCore.Identity.SignInResult? signInResult;

        if (!ModelState.IsValid)
            return View(viewModel);

        try
        {
            signInResult = await _accountIdentityManager.TwoFactorAuthenticatorSignInAsync(viewModel.Code!, viewModel.RememberMe, true)
            ?? throw new InvalidOperationException("No se pudo validar el código de verificación.");
        }
        catch (InvalidOperationException ex)
        {
            return _errorController.HandleException(ex, nameof(VerifyAuthenticatorCode), "No se pudo validar el código de verificación.");
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(VerifyAuthenticatorCode));
        }

        if (signInResult.Succeeded)
            return LocalRedirect(viewModel.ReturnUrl);

        else if (signInResult.IsLockedOut)
            return View("AccountLocked");

        else
            ModelState.AddModelError(string.Empty, "El código de verificación no es válido o ha expirado.");

        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> DisableTwoFactorAuthentication()
    {
        try
        {
            var identityUser = await _accountIdentityManager.GetUserAsync(User) ?? throw new InvalidOperationException("El usuario no existe.");
            var identityResultReset = await _accountIdentityManager.ResetAuthenticatorKeyAsync(identityUser);
            var identityResultSetTwoFactor = await _accountIdentityManager.SetTwoFactorEnabledAsync(identityUser, false);

            if (!identityResultSetTwoFactor.Succeeded || !identityResultReset.Succeeded)
                throw new InvalidOperationException("No se pudo deshabilitar la autenticación de dos factores.");
        }
        catch (InvalidOperationException ex)
        {
            return _errorController.HandleException(ex, nameof(DisableTwoFactorAuthentication), "usuario no encontrado");
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(DisableTwoFactorAuthentication));
        }

        return RedirectToAction(nameof(HomeController.Index), "Home");
    }
    #endregion
}
