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
            if (string.IsNullOrEmpty(id)) throw new ArgumentNullException("El parámetro id no debe estar nulo o vacío", nameof(id));

            var userDto = await _userAccountManager.FindByIdAsync(id);

            var viewModel = userDto!.ToViewModel();
            return View(viewModel);
        }
        catch (ArgumentNullException ex)
        {
            return _errorController.HandleException(ex, nameof(EditProfile), "id nulo");
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
        if (ModelState.IsValid)
        {
            try
            {
                var userDto = viewModel.ToDto();
                var updateUserResult = await _accountIdentityManager.UpdateUserAsync(userDto);
                if (updateUserResult.Succeeded)
                    return RedirectToAction(nameof(HomeController.Index), "Home");

                _errorController.HandleErrors(updateUserResult.Errors);
            }
            catch (Exception ex)
            {
                return _errorController.HandleException(ex, nameof(EditProfile));
            }
        }
        return View(viewModel);
    }
    #endregion

    #region Change password
    [HttpGet]
    public IActionResult ChangePassword() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            try
            {
                var resetPasswordResult = await _accountIdentityManager.ChangePasswordAsync(User, viewModel.Password!);
                if (resetPasswordResult.Succeeded)
                    return RedirectToAction(nameof(ConfirmationChangePassword));

                _errorController.HandleErrors(resetPasswordResult.Errors);
            }
            catch (Exception ex)
            {
                return _errorController.HandleException(ex, nameof(ChangePassword));
            }
        }
        return View(viewModel);
    }

    [HttpGet]
    public IActionResult ConfirmationChangePassword() => View();
    #endregion

    #region Settings
    [HttpGet]
    public async Task<IActionResult> Settings()
    {
        bool isTwoFactorEnabled = false;
        try
        {
            isTwoFactorEnabled = await _accountIdentityManager.IsTwoFactorEnabled(User);
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(Settings));
        }
        ViewData["IsTwoFactorAuthenticationActive"] = isTwoFactorEnabled;
        return View();
    }
    #endregion
}
