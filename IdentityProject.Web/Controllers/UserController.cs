using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Users;
using IdentityProject.Web.Interfaces.Controllers;
using IdentityProject.Web.Models;
using IdentityProject.Web.Models.MapperExtensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;
[Authorize]
public class UserController(IErrorController errorController, IAccountIdentityManager accountIdentityManager, IUsersService userAccountManager) : Controller
{
    private readonly IErrorController _errorController = errorController;
    private readonly IAccountIdentityManager _accountIdentityManager = accountIdentityManager;
    private readonly IUsersService _userAccountManager = userAccountManager;

    #region Edit profile
    [HttpGet]
    public async Task<IActionResult> EditProfile(string id)
    {
        try
        {
            var userDto = await _userAccountManager.FindByIdAsync(id ?? throw new ArgumentNullException(nameof(id)))
                ?? throw new InvalidOperationException("El usuario no existe");

            var viewModel = userDto.ToViewModel();
            return View(viewModel);
        }
        catch (ArgumentNullException ex)
        {
            return _errorController.HandleException(ex, nameof(EditProfile), "id nulo");
        }
        catch (InvalidOperationException ex)
        {
            return _errorController.HandleException(ex, nameof(EditProfile), "usuario no encontrado");
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(EditProfile));
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditProfile(EditProfileViewModel viewModel)
    {
        try
        {
            if (ModelState.IsValid)
            {
                var userDto = viewModel.ToDto();
                var resultDto = await _accountIdentityManager.UpdateUserAsync(userDto);
                if (resultDto.Succeeded)
                    return RedirectToAction(nameof(HomeController.Index), "Home");

                _errorController.HandleErrors(resultDto.Errors);
            }

            return View(viewModel);
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(EditProfile));
        }
    }
    #endregion

    #region Change password
    [HttpGet]
    public IActionResult ChangePassword() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel viewModel)
    {
        try
        {
            if (ModelState.IsValid)
            {
                var userId = await _accountIdentityManager.GetUserAsync(User) ?? throw new InvalidOperationException("El usuario no existe");
                var token = await _accountIdentityManager.GeneratePasswordResetTokenAsync(userId);
                var resultDto = await _accountIdentityManager.ResetPasswordAsync(userId, token, viewModel.Password!);
                if (resultDto.Succeeded)
                    return RedirectToAction(nameof(ConfirmationChangePassword));

                _errorController.HandleErrors(resultDto.Errors);
            }

            return View(viewModel);
        }
        catch (InvalidOperationException ex)
        {
            return _errorController.HandleException(ex, nameof(ChangePassword), "usuario no encontrado");
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(ChangePassword));
        }
    }

    [HttpGet]
    public IActionResult ConfirmationChangePassword() => View();
    #endregion

    #region Settings
    [HttpGet]
    public async Task<IActionResult> Settings()
    {
        try
        {
            var isTwoFactorEnabled = await _accountIdentityManager.IsTwoFactorEnabled(User);
            ViewData["IsTwoFactorAuthenticationActive"] = isTwoFactorEnabled;
            return View();
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(Settings));
        }
    }
    #endregion
}
