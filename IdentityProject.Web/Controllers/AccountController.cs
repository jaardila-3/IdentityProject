using IdentityProject.Web.Models;
using IdentityProject.Web.Models.MapperExtensions;
using IdentityProject.Web.Interfaces.Controllers;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Email;
using IdentityProject.Common.Enums;
using IdentityProject.Common.ExtensionMethods;
using IdentityProject.Common.Dto;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Authorization;
using System.Text.Encodings.Web;

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
            await _accountIdentityManager.SetupRolesAsync();
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Register), "Error al crear roles");
            throw;
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
                var (resultDtoUsercreated, userId) = await _accountIdentityManager.CreateUserAsync(userToCreateDto, viewModel.Password!, RoleTypeString.RegisteredUser);

                if (resultDtoUsercreated.Succeeded)
                {
                    if (!await SendEmailConfirmationRegisterAsync(userId, viewModel.Email!))
                    {
                        TempData["Error"] = "No se pudo enviar el email de confirmación";
                        Console.Error.WriteLine("No se pudo enviar el email de confirmación por que no se genero el token.");
                    }
                    return RedirectToAction(nameof(HomeController.Index), "Home");
                }
                foreach (var error in resultDtoUsercreated.Errors) ModelState.AddModelError(string.Empty, error);
            }
            catch (Exception ex)
            {
                _errorController.LogException(ex, nameof(Register));
                throw;
            }
        }
        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> RegisterAdmin()
    {
        try
        {
            await _accountIdentityManager.SetupRolesAsync();
            RegisterViewModel viewModel = new() { Roles = await GetRoleItemsAsync() };
            return View(viewModel);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(RegisterAdmin));
            throw;
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RegisterAdmin(RegisterViewModel viewModel)
    {
        if (string.IsNullOrEmpty(viewModel.SelectedRole)) ModelState.AddModelError(nameof(viewModel.SelectedRole), "Debe seleccionar un rol");

        if (ModelState.IsValid)
        {
            try
            {
                viewModel.State = true;
                var userToCreateDto = viewModel.ToDto();
                var (resultDtoUsercreated, userId) = await _accountIdentityManager.CreateUserAsync(userToCreateDto, viewModel.Password!, viewModel.SelectedRole!, false);

                if (resultDtoUsercreated.Succeeded)
                {
                    if (!await SendEmailConfirmationRegisterAsync(userId, viewModel.Email!))
                    {
                        TempData["Error"] = "No se pudo enviar el email de confirmación";
                        Console.Error.WriteLine("No se pudo enviar el email de confirmación por que no se genero el token.");
                    }
                    TempData["Success"] = "Usuario creado correctamente";
                    return RedirectToAction(nameof(HomeController.Index), "Home");
                }
                foreach (var error in resultDtoUsercreated.Errors) ModelState.AddModelError(string.Empty, error);
            }
            catch (Exception ex)
            {
                _errorController.LogException(ex, nameof(RegisterAdmin));
                throw;
            }
        }

        viewModel.Roles = await GetRoleItemsAsync();
        return View(viewModel);
    }

    [HttpGet]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token)) return BadRequest("La confirmación de correo electrónico requiere un ID de usuario y un token válidos. Verifique la URL y vuelva a intentarlo.");
        bool isConfirmEmail = false;
        try
        {
            isConfirmEmail = await _accountIdentityManager.ConfirmEmailAsync(userId, token);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(ConfirmEmail));
            throw;
        }
        return isConfirmEmail ? View() : StatusCode(500, "Error al confirmar el correo");
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
                _errorController.LogException(ex, nameof(Login));
                throw;
            }
            #region Two Factor Authentication
            if (signInResultDto.RequiresTwoFactor) return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnUrl, viewModel.RememberMe });
            #endregion
            if (signInResultDto.Succeeded) return LocalRedirect(returnUrl);
            if (signInResultDto.IsLockedOut) return View("AccountLocked");
            if (signInResultDto.IsNotAllowed) ModelState.AddModelError(string.Empty, "Acceso inválido. Por favor, confirme su cuenta si aún no lo ha hecho.");
            else ModelState.AddModelError(string.Empty, "Acceso inválido.");
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
            _errorController.LogException(ex, nameof(Logout));
            throw;
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
                var (userId, token) = await _accountIdentityManager.GeneratePasswordResetTokenAsync(viewModel.Email!);
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
                _errorController.LogException(ex, nameof(ForgotPassword));
                throw;
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
    public IActionResult ResetPassword(string code) => string.IsNullOrEmpty(code) ? BadRequest("Se debe proporcionar un código para restablecer la contraseña.") : View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(ResetPasswordViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            try
            {
                var resetPasswordResult = await _accountIdentityManager.ResetPasswordAsync(viewModel.Email!, viewModel.Code!, viewModel.Password!);
                if (resetPasswordResult.Succeeded) return RedirectToAction(nameof(ResetPasswordConfirmation));
                foreach (var error in resetPasswordResult.Errors) ModelState.AddModelError(string.Empty, error);
            }
            catch (Exception ex)
            {
                _errorController.LogException(ex, nameof(ResetPassword));
                throw;
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
            roleItems.Add(new SelectListItem()
            {
                Value = role,
                Text = role
            });
        }
        return roleItems;
    }
    private async Task<List<SelectListItem>> GetRoleItemsEnumAsync()
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

    private async Task<bool> SendEmailConfirmationRegisterAsync(string userId, string email)
    {
        var token = await _accountIdentityManager.GenerateEmailConfirmationTokenAsync(userId);
        if (string.IsNullOrEmpty(token)) return false;

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
        return true;
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
            var (email, token) = await _accountIdentityManager.InitiateTwoFactorAuthenticationAsync(User);
            if (string.IsNullOrEmpty(email)) return BadRequest("No se pudo obtener los datos de la cuenta del usuario.");
            if (string.IsNullOrEmpty(token)) return BadRequest("No se pudo generar el token de autenticación.");
            // Create QR code
            string authenticatorUrlFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            string authenticatorUrl = string.Format(authenticatorUrlFormat, _urlEncoder.Encode("IdentityProject"), _urlEncoder.Encode(email), token);

            var viewModel = new TwoFactorAuthenticationViewModel() { Token = token, QrCodeUri = authenticatorUrl };
            return View(viewModel);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(ActivateTwoFactorAuthentication));
            throw;
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
                _errorController.LogException(ex, nameof(ActivateTwoFactorAuthentication));
                throw;
            }

            if (isConfirm)
                return RedirectToAction(nameof(AuthenticatorConfirmation));

            ModelState.AddModelError(string.Empty, "La autenticación de dos factores no ha sido validada correctamente.");
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
            _errorController.LogException(ex, nameof(VerifyAuthenticatorCode));
            throw;
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

        if (!ModelState.IsValid) return View(viewModel);
        try
        {
            signInResultDto = await _accountIdentityManager.TwoFactorAuthenticatorSignInAsync(viewModel.Code!, viewModel.RememberMe, false);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(VerifyAuthenticatorCode));
            throw;
        }

        if (signInResultDto.Succeeded) return LocalRedirect(viewModel.ReturnUrl);
        if (signInResultDto.IsLockedOut) return View("AccountLocked");
        if (signInResultDto.IsNotAllowed) ModelState.AddModelError(string.Empty, "Acceso inválido. Por favor, confirme su cuenta si aún no lo ha hecho.");
        else ModelState.AddModelError(string.Empty, "El código de verificación no es válido o ha expirado.");
        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> DisableTwoFactorAuthentication()
    {
        bool disable = false;
        try
        {
            disable = await _accountIdentityManager.DisableTwoFactorAuthenticationAsync(User);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(DisableTwoFactorAuthentication));
            throw;
        }

        if (!disable) TempData["Error"] = "La autenticación de dos factores No pudo ser desactivada";

        TempData["Success"] = "La autenticación de dos factores ha sido desactivada";
        return RedirectToAction(nameof(HomeController.Index), "Home");
    }
    #endregion
}
