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
                var (resultDtoUsercreated, userId) = await _accountIdentityManager.CreateUserAsync(userToCreateDto, viewModel.Password!, nameof(RoleType.Usuario_Registrado));

                if (resultDtoUsercreated.Succeeded)
                {
                    await SendEmailConfirmationRegisterAsync(userId, viewModel.Email!);
                    return RedirectToAction(nameof(HomeController.Index), "Home");
                }
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
            var (resultDtoUsercreated, userId) = await _accountIdentityManager.CreateUserAsync(userToCreateDto, viewModel.Password!, viewModel.SelectedRole, false);

            if (resultDtoUsercreated.Succeeded)
            {
                await SendEmailConfirmationRegisterAsync(userId, viewModel.Email!);
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
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
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException("El parámetro userId no debe estar vacío", nameof(userId));
        if (string.IsNullOrWhiteSpace(token)) throw new ArgumentException("El parámetro token no debe estar vacío", nameof(token));

        try
        {
            await _accountIdentityManager.ConfirmEmailAsync(userId, token);
        }
        catch (ArgumentException ex)
        {
            return _errorController.HandleException(ex, nameof(ConfirmEmail), "Parámetro vacío");
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(ConfirmEmail));
        }
        return View();
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
                var (userId, token) = await _accountIdentityManager.GeneratePasswordResetToken(viewModel.Email!);
                if (string.IsNullOrEmpty(userId))
                {
                    ModelState.AddModelError(string.Empty, "El correo no se encuentra registrado.");
                    return View(viewModel);
                }
                var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { userId, code = token }, protocol: HttpContext.Request.Scheme);
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
    public IActionResult ResetPassword(string code)
    {
        try
        {
            return string.IsNullOrEmpty(code) ? throw new ArgumentException(nameof(code)) : View();
        }
        catch (ArgumentException ex)
        {
            return _errorController.HandleException(ex, nameof(ResetPassword), "código nulo o vacío");
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
                var resetPasswordResult = await _accountIdentityManager.ResetPassword(viewModel.Email!, viewModel.Code!, viewModel.Password!);
                if (resetPasswordResult.Succeeded) return RedirectToAction(nameof(ResetPasswordConfirmation));
                _errorController.HandleErrors(resetPasswordResult.Errors);
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
        var callbackUrl = Url.Action(nameof(ConfirmEmail), "Account", new { userId, token }, protocol: HttpContext.Request.Scheme);
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
            var (token, email) = await _accountIdentityManager.InitiateTwoFactorAuthenticationAsync(User);
            // Create QR code
            string authenticatorUrlFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            string authenticatorUrl = string.Format(authenticatorUrlFormat, _urlEncoder.Encode("IdentityProject"), _urlEncoder.Encode(email), token);

            var viewModel = new TwoFactorAuthenticationViewModel() { Token = token, QrCodeUri = authenticatorUrl };
            return View(viewModel);
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
            bool isConfirm = false;
            try
            {
                isConfirm = await _accountIdentityManager.ConfirmTwoFactorAuthenticationAsync(User, viewModel.Code!);
            }
            catch (Exception ex)
            {
                return _errorController.HandleException(ex, nameof(ActivateTwoFactorAuthentication));
            }

            if (isConfirm)
                return RedirectToAction(nameof(AuthenticatorConfirmation));

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
            await _accountIdentityManager.GetTwoFactorAuthenticationUserAsync();
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
        ResultDto signInResultDto;

        if (!ModelState.IsValid)
            return View(viewModel);

        try
        {
            signInResultDto = await _accountIdentityManager.TwoFactorAuthenticatorSignInAsync(viewModel.Code!, viewModel.RememberMe, false);
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(VerifyAuthenticatorCode));
        }

        if (signInResultDto.Succeeded)
            return LocalRedirect(viewModel.ReturnUrl);

        else if (signInResultDto.IsLockedOut || signInResultDto.IsNotAllowed)
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
            await _accountIdentityManager.DisableTwoFactorAuthenticationAsync(User);
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(DisableTwoFactorAuthentication));
        }

        return RedirectToAction(nameof(HomeController.Index), "Home");
    }
    #endregion
}
