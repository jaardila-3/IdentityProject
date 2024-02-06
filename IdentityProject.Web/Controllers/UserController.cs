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
            if (string.IsNullOrEmpty(id)) return NotFound();
            var userDto = await _userAccountManager.FindByIdAsync(id);
            var viewModel = userDto!.ToViewModel();
            return View(viewModel);
        }        
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(EditProfile));
            throw;
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
                {
                    TempData["Success"] = "Perfil actualizado correctamente";
                    return RedirectToAction(nameof(HomeController.Index), "Home");
                }

                foreach (var error in updateUserResult.Errors) ModelState.AddModelError(string.Empty, error);
            }
            catch (Exception ex)
            {
                _errorController.LogException(ex, nameof(EditProfile));
                throw;
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

                foreach (var error in resetPasswordResult.Errors) ModelState.AddModelError(string.Empty, error);
            }
            catch (Exception ex)
            {
                _errorController.LogException(ex, nameof(ChangePassword));
                throw;
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
            _errorController.LogException(ex, nameof(Settings));
            throw;
        }
        ViewData["IsTwoFactorAuthenticationActive"] = isTwoFactorEnabled;
        return View();
    }
    #endregion
}
