using IdentityProject.Web.Models;
using IdentityProject.Web.Models.MapperExtensions;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services;
using IdentityProject.Common.Enums;
using IdentityProject.Common.ExtensionMethods;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Authorization;
using System.Diagnostics;
using System.Text.Encodings.Web;

namespace IdentityProject.Web.Controllers;

[Authorize]
public class AccountController(IAccountManager accountManager, IEmailService emailService, UrlEncoder urlEncoder) : Controller
{
    private readonly IAccountManager _accountManager = accountManager;
    private readonly IEmailService _emailService = emailService;
    private readonly UrlEncoder _urlEncoder = urlEncoder;

    #region Register
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Register()
    {
        await _accountManager.CreateRolesAsync();
        RegisterViewModel model = new();
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (ModelState.IsValid)
        {
            model.State = true;
            var user = model.ToDto();
            var (identityResult, userId) = await _accountManager.CreateUserAsync(user, model.Password!);

            if (identityResult.Succeeded)
            {
                var identityUser = await _accountManager.FindByIdAsync(userId);
                if (identityUser is null)
                    RedirectToAction(nameof(Error));

                await _accountManager.AddToRoleAsync(identityUser!, nameof(RoleType.RegisteredUser));

                await SendEmailConfirmationRegisterAsync(identityUser!, model.Email!);

                await _accountManager.SignInAsync(identityUser!, false);
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            ValidateErrors(identityResult);
        }

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> RegisterAdmin()
    {
        await _accountManager.CreateRolesAsync();
        List<SelectListItem> roleItems = await GetRoleItemsAsync();

        RegisterViewModel model = new()
        {
            Roles = roleItems
        };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterAdmin(RegisterViewModel model)
    {
        if (ModelState.IsValid)
        {
            model.State = true;
            var user = model.ToDto();
            var (identityResult, userId) = await _accountManager.CreateUserAsync(user, model.Password!);

            if (identityResult.Succeeded)
            {
                var identityUser = await _accountManager.FindByIdAsync(userId);
                if (identityUser is null)
                    RedirectToAction(nameof(Error));

                if (!string.IsNullOrEmpty(model.SelectedRole) && await _accountManager.RoleExistsAsync(model.SelectedRole!))
                    await _accountManager.AddToRoleAsync(identityUser!, model.SelectedRole!);
                else
                    await _accountManager.AddToRoleAsync(identityUser!, nameof(RoleType.RegisteredUser));

                await SendEmailConfirmationRegisterAsync(identityUser!, model.Email!);

                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            ValidateErrors(identityResult);
        }

        List<SelectListItem> roles = await GetRoleItemsAsync();
        model.Roles = roles;

        return View(model);
    }


    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string userId, string code)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            RedirectToAction(nameof(Error));

        var user = await _accountManager.FindByIdAsync(userId);
        if (user is null)
            RedirectToAction(nameof(Error));

        var result = await _accountManager.ConfirmEmailAsync(user!, code);
        if (!result.Succeeded)
            RedirectToAction(nameof(Error));

        return View(nameof(ConfirmEmail));
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
    public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
    {
        ViewData["ReturnUrl"] = returnUrl;
        returnUrl ??= Url.Content("~/");

        if (ModelState.IsValid)
        {
            var result = await _accountManager.PasswordSignInAsync(model.UserName!, model.Password!, model.RememberMe, true);

            if (result.Succeeded)
                return LocalRedirect(returnUrl);

            else if (result.IsLockedOut)
                return View("AccountLocked");

            #region Two Factor Authentication
            else if (result.RequiresTwoFactor)
                return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnUrl, model.RememberMe });
            #endregion

            else
            {
                ModelState.AddModelError(string.Empty, "Acceso inválido.");
                return View(model);
            }
        }

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Logout()
    {
        await _accountManager.SignOutAsync();
        return RedirectToAction(nameof(HomeController.Index), "Home");
    }
    #endregion

    #region Forgot Password
    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPassword()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _accountManager.FindByEmailAsync(model.Email!);
            if (user is null)
            {
                ModelState.AddModelError(string.Empty, "El correo no se encuentra registrado.");
                return View(model);
            }

            var code = await _accountManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Action(nameof(ResetPassword), "Account", new { userId = user.Id, code }, protocol: HttpContext.Request.Scheme);

            var subject = "Recuperar contraseña - IdentityProject";
            var bodyHtml = @$"<p>Estimado usuario,</p>
                <p>Hemos recibido una solicitud para restablecer la contraseña de su cuenta en IdentityProject. Si usted hizo esta solicitud, puede seguir el siguiente enlace para crear una nueva contraseña:</p>
                <p><a href='{callbackUrl}'>Restablecer contraseña</a></p>
                <p>Este enlace es válido por 24 horas. Si no lo usa dentro de ese plazo, deberá solicitar otro cambio de contraseña.</p>
                <p>Si usted no hizo esta solicitud, puede ignorar este correo. Su contraseña actual no se verá afectada.</p>
                <p>Gracias por usar IdentityProject.</p>
                <p>Atentamente,</p>
                <p>El equipo de IdentityProject</p>";

            await _emailService.SendEmailAsync(model.Email!, subject, bodyHtml);

            return RedirectToAction(nameof(ForgotPasswordConfirmation));
        }
        return View(model);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ForgotPasswordConfirmation()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPassword(string? code = null)
    {
        return code is null ? RedirectToAction(nameof(Error)) : View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _accountManager.FindByEmailAsync(model.Email!);
            if (user is null)
            {
                ModelState.AddModelError(string.Empty, "El correo no se encuentra registrado.");
                return View(model);
            }

            var result = await _accountManager.ResetPasswordAsync(user, model.Code!, model.Password!);
            if (result.Succeeded)
                return RedirectToAction(nameof(ResetPasswordConfirmation));

            ValidateErrors(result);
        }

        return View(model);
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult ResetPasswordConfirmation()
    {
        return View();
    }
    #endregion

    #region Helpers
    private void ValidateErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
            ModelState.AddModelError(string.Empty, error.Description);
    }

    private async Task<List<SelectListItem>> GetRoleItemsAsync()
    {
        var roles = await _accountManager.GetRolesListAsync() ?? [];
        List<SelectListItem> roleItems = [];

        foreach (var role in roles)
        {
            if (Enum.TryParse<RoleType>(role.Name!, out var roleType))
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

    private async Task SendEmailConfirmationRegisterAsync(IdentityUser user, string email)
    {
        var token = await _accountManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action(nameof(ConfirmEmail), "Account", new { userId = user.Id, code = token }, protocol: HttpContext.Request.Scheme);
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

    #region Error
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    [AllowAnonymous]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
    
    [HttpGet]
    [AllowAnonymous]
    public IActionResult AccessDenied()
    {
        return View();
    }
    #endregion

    #region Two Factor Authentication
    [HttpGet]
    public async Task<IActionResult> ActivateTwoFactorAuthentication()
    {
        var user = await _accountManager.GetUserAsync(User);
        if (user is null)
            return RedirectToAction(nameof(Error));

        var result = await _accountManager.ResetAuthenticatorKeyAsync(user);
        if (!result.Succeeded)
            RedirectToAction(nameof(Error));

        var token = await _accountManager.GetAuthenticatorKeyAsync(user);
        // Create QR code
        string authenticatorUrlFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        string authenticatorUrl = string.Format(authenticatorUrlFormat, _urlEncoder.Encode("IdentityProject"), _urlEncoder.Encode(user!.Email!), token);

        var model = new TwoFactorAuthenticationViewModel() { Token = token, QrCodeUri = authenticatorUrl };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ActivateTwoFactorAuthentication(TwoFactorAuthenticationViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _accountManager.GetUserAsync(User);
            if (user is null)
                return RedirectToAction(nameof(Error));

            var Succeeded = await _accountManager.VerifyTwoFactorTokenAsync(user, model.Code!);
            if (Succeeded)
            {
                var result = await _accountManager.SetTwoFactorEnabledAsync(user, true);
                if (!result.Succeeded)
                    RedirectToAction(nameof(Error));
            }
            else
            {
                ModelState.AddModelError(string.Empty, "La autenticación de dos factores no ha sido validada correctamente.");
                return View(model);
            }
        }
        return RedirectToAction(nameof(AuthenticatorConfirmation));
    }

    [HttpGet]
    public IActionResult AuthenticatorConfirmation()
    {
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        var user = await _accountManager.GetTwoFactorAuthenticationUserAsync();
        if (user is null)
            RedirectToAction(nameof(Error));

        ViewData["ReturnUrl"] = returnUrl;

        return View(new VerifyAuthenticatorCodeViewModel { ReturnUrl = returnUrl, RememberMe = rememberMe });
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorCodeViewModel model)
    {
        model.ReturnUrl ??= Url.Content("~/");
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var result = await _accountManager.TwoFactorAuthenticatorSignInAsync(model.Code!, model.RememberMe, true);
        if (result.Succeeded)
        {
            return LocalRedirect(model.ReturnUrl);
        }
        else if (result.IsLockedOut)
        {
            return View("AccountLocked");
        }
        else
        {
            ModelState.AddModelError(string.Empty, "El código de verificación no es válido o ha expirado.");
            return View(model);
        }
    }

    [HttpGet]
    public async Task<IActionResult> DisableTwoFactorAuthentication()
    {
        var user = await _accountManager.GetUserAsync(User);
        if (user is null)
            return RedirectToAction(nameof(Error));

        var resultReset = await _accountManager.ResetAuthenticatorKeyAsync(user);
        var resultSet = await _accountManager.SetTwoFactorEnabledAsync(user, false);

        if (!resultSet.Succeeded || !resultReset.Succeeded)
            RedirectToAction(nameof(Error));

        return RedirectToAction(nameof(HomeController.Index), "Home");
    }
    #endregion
}
