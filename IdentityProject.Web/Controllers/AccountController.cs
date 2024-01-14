using IdentityProject.Domain.Entities;
using IdentityProject.Web.Models;
using IdentityProject.Business.Interfaces.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Diagnostics;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc.Rendering;
using IdentityProject.Web.Models.Enum;
using Microsoft.EntityFrameworkCore;
using IdentityProject.Common.ExtensionMethods;
using IdentityProject.Web.Models.MapperExtensions;

namespace IdentityProject.Web.Controllers;

[Authorize]
public class AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailService emailService, UrlEncoder urlEncoder, RoleManager<IdentityRole> roleManager) : Controller
{
    private readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly RoleManager<IdentityRole> _roleManager = roleManager;
    private readonly SignInManager<IdentityUser> _signInManager = signInManager;
    private readonly IEmailService _emailService = emailService;
    private readonly UrlEncoder _urlEncoder = urlEncoder;

    #region Register
    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> Register()
    {
        //roles creation
        if (!(await _roleManager.RoleExistsAsync(nameof(RoleType.RegisteredUser))))
            await _roleManager.CreateAsync(new IdentityRole(nameof(RoleType.RegisteredUser)));

        if (!(await _roleManager.RoleExistsAsync(nameof(RoleType.Admin))))
            await _roleManager.CreateAsync(new IdentityRole(nameof(RoleType.Admin)));

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
            var user = model.ToDomain();
            user.State = true;
            var result = await _userManager.CreateAsync(user, model.Password!);

            if (result.Succeeded)
            {
                //role assignment
                await _userManager.AddToRoleAsync(user, nameof(RoleType.RegisteredUser));

                await SendEmailConfirmationRegisterAsync(user, model.Email!);

                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            ValidateErrors(result);
        }

        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> RegisterAdmin()
    {
        await CreateRolesAsync();
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
            var user = model.ToDomain();
            user.State = true;
            var result = await _userManager.CreateAsync(user, model.Password!);

            if (result.Succeeded)
            {
                //selected role in register
                if (!string.IsNullOrEmpty(model.SelectedRole) && await _roleManager.RoleExistsAsync(model.SelectedRole!))
                    await _userManager.AddToRoleAsync(user, model.SelectedRole!);
                else
                    await _userManager.AddToRoleAsync(user, nameof(RoleType.RegisteredUser));

                await SendEmailConfirmationRegisterAsync(user, model.Email!);

                //await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            ValidateErrors(result);
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

        var user = await _userManager.FindByIdAsync(userId!);
        if (user == null)
            RedirectToAction(nameof(Error));

        var result = await _userManager.ConfirmEmailAsync(user!, code!);
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
            var result = await _signInManager.PasswordSignInAsync(model.UserName!, model.Password!, model.RememberMe, lockoutOnFailure: true);

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
        await _signInManager.SignOutAsync();
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
            var user = await _userManager.FindByEmailAsync(model.Email!);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "El correo no se encuentra registrado.");
                return View(model);
            }

            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
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
        return code == null ? RedirectToAction(nameof(Error)) : View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.FindByEmailAsync(model.Email!);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "El correo no se encuentra registrado.");
                return View(model);
            }

            var result = await _userManager.ResetPasswordAsync(user, model.Code!, model.Password!);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetPasswordConfirmation));
            }

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
    [AllowAnonymous]
    private void ValidateErrors(IdentityResult result)
    {
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }

    private async Task CreateRolesAsync()
    {
        if (!(await _roleManager.RoleExistsAsync(nameof(RoleType.RegisteredUser))))
            await _roleManager.CreateAsync(new IdentityRole(nameof(RoleType.RegisteredUser)));

        if (!(await _roleManager.RoleExistsAsync(nameof(RoleType.Admin))))
            await _roleManager.CreateAsync(new IdentityRole(nameof(RoleType.Admin)));
    }

    private async Task<List<SelectListItem>> GetRoleItemsAsync()
    {
        var roles = await _roleManager.Roles.ToListAsync();
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

    [AllowAnonymous]
    private async Task SendEmailConfirmationRegisterAsync(AppUser user, string email)
    {
        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action(nameof(ConfirmEmail), "Account", new { userId = user.Id, code }, protocol: HttpContext.Request.Scheme);
        var subject = "Confirmar su cuenta de IdentityProject";
        var bodyHtml = @$"<p>Hola,</p>
                    <p>Usted ha sido registrado en IdentityProject. Estamos encantados de tenerte como usuario.</p>
                    <p>Para completar tu registro y acceder a todas las funcionalidades de la aplicación, solo tienes que hacer clic en el siguiente enlace:</p>
                    <p><a href='{callbackUrl}'>Confirmar cuenta</a></p>
                    <p>Este enlace es válido por 24 horas. Si no lo usas dentro de ese plazo, deberás registrarte de nuevo.</p> 
                    <p>Si tienes alguna duda o problema, puedes contactarnos en (email de soporte).</p>
                    <p>¡Esperamos que disfrutes de IdentityProject!</p>
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
    #endregion

    #region Two Factor Authentication
    [HttpGet]
    public async Task<IActionResult> ActivateTwoFactorAuthentication()
    {
        var user = await _userManager.GetUserAsync(User);
        await _userManager.ResetAuthenticatorKeyAsync(user!);
        var token = await _userManager.GetAuthenticatorKeyAsync(user!);

        // Create QR code
        string authenticatorUrlFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        string authenticatorUrl = string.Format(authenticatorUrlFormat, _urlEncoder.Encode("IdentityProject"), _urlEncoder.Encode(user!.Email!), token);

        var model = new TwoFactorAuthenticationViewModel() { Token = token!, QrCodeUri = authenticatorUrl };
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ActivateTwoFactorAuthentication(TwoFactorAuthenticationViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.GetUserAsync(User);
            var Succeeded = await _userManager.VerifyTwoFactorTokenAsync(user!, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code!);
            if (Succeeded)
            {
                await _userManager.SetTwoFactorEnabledAsync(user!, true);
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
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            RedirectToAction(nameof(Error));
        }

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

        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code!, model.RememberMe, rememberClient: true);
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
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            return RedirectToAction(nameof(Error));
        }
        await _userManager.ResetAuthenticatorKeyAsync(user);
        bool enabled = false;
        await _userManager.SetTwoFactorEnabledAsync(user, enabled);
        return RedirectToAction(nameof(HomeController.Index), "Home");
    }
    #endregion
}
