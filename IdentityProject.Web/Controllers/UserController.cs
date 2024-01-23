using System.Diagnostics;
using IdentityProject.Business.Interfaces.Features;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Web.Models;
using IdentityProject.Web.Models.MapperExtensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;

[Authorize]
public class UserController(IIdentityManager identityManager, IUserAccountManager userAccountManager) : Controller
{
    private readonly IIdentityManager _identityManager = identityManager;
    private readonly IUserAccountManager _userAccountManager = userAccountManager;

    #region Edit profile
    [HttpGet]
    public async Task<IActionResult> EditProfile(string id)
    {
        if (id is null)
            RedirectToAction(nameof(Error));

        var userDto = await _userAccountManager.FindByIdAsync(id!);
        if (userDto is null)
            RedirectToAction(nameof(Error));

        var viewModel = userDto!.ToViewModel();

        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> EditProfile(EditProfileViewModel model)
    {
        if (ModelState.IsValid)
        {
            var userDto = model.ToDto();
            var identityResult = await _identityManager.UpdateUserAsync(userDto);
            if (identityResult.Succeeded)
                return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        return View(model);
    }
    #endregion

    #region Change password
    [HttpGet]
    public IActionResult ChangePassword() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
    {
        if (ModelState.IsValid)
        {
            var identityUser = await _identityManager.GetUserAsync(User);
            if (identityUser is null)
                return RedirectToAction(nameof(Error));

            var token = await _identityManager.GeneratePasswordResetTokenAsync(identityUser);
            var identityResult = await _identityManager.ResetPasswordAsync(identityUser, token, model.Password!);
            if (identityResult.Succeeded)
                return RedirectToAction(nameof(ConfirmationChangePassword));
            else
                return View(model);
        }

        return View(model);
    }

    [HttpGet]
    public IActionResult ConfirmationChangePassword() => View();
    #endregion

    #region Settings
    [HttpGet]
    public async Task<IActionResult> Settings()
    {
        var user = await _identityManager.GetUserAsync(User);

        if (user is null)
            ViewData["IsTwoFactorAuthenticationActive"] = false;
        else
            ViewData["IsTwoFactorAuthenticationActive"] = user.TwoFactorEnabled;

        return View();
    }
    #endregion

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
}
