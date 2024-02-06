using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Roles;
using IdentityProject.Business.Interfaces.Services.Users;
using IdentityProject.Common.Enums;
using IdentityProject.Web.Interfaces.Controllers;
using IdentityProject.Web.Models;
using IdentityProject.Web.Models.MapperExtensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace IdentityProject.Web.Controllers;
[Authorize]
public class UserController(IErrorController errorController, IAccountIdentityManager accountIdentityManager, IUsersService userService, IRolesService rolesService) : Controller
{
    private readonly IErrorController _errorController = errorController;
    private readonly IAccountIdentityManager _accountIdentityManager = accountIdentityManager;
    private readonly IUsersService _userService = userService;
    private readonly IRolesService _rolesService = rolesService;

    [HttpGet]
    [Authorize(Roles = nameof(RoleType.Admin))]
    public async Task<IActionResult> Index()
    {
        List<UserViewModel>? viewModel = [];
        try
        {
            var users = await _userService.GetListUsersAsync() ?? [];
            viewModel = users.Select(u => u.ToViewModel()).ToList();
            var userRoles = await _rolesService.GetListUserRolesAsync() ?? [];
            var roles = await _rolesService.GetListRolesAsync() ?? [];
            foreach (var user in viewModel)
            {
                var userRole = userRoles.FirstOrDefault(ur => ur.UserId == user.Id);
                if (userRole is not null)
                {
                    user.RoleId = userRole.RoleId;
                    user.RoleName = roles.FirstOrDefault(r => r.Id == userRole.RoleId)?.Name;
                }
            }
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Index));
            throw;
        }
        return View(viewModel);
    }

    [HttpGet]
    [Authorize(Roles = nameof(RoleType.Admin))]
    public async Task<IActionResult> Edit(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        try
        {
            var user = await _userService.FindUserByIdAsync(id); ;
            if (user is null) return NotFound();
            var viewModel = user.ToViewModel();

            var userRole = await _rolesService.GetUserRolesByUserIdAsync(id);
            if (userRole is null) return NotFound("No se encontraron roles asignados al usuario.");
            viewModel.RoleId = userRole.RoleId;
            
            var role = await _rolesService.GetRoleByIdAsync(userRole.RoleId!);
            if (role is null) return NotFound("No existe el rol.");
            viewModel.RoleName = role.Name;

            var roles = await _rolesService.GetListRolesAsync();
            viewModel.Roles = roles?.Select(r => new SelectListItem { Value = r.Id, Text = r.Name }).ToList();
            return View(viewModel);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Edit));
            throw;
        }
    }

    #region Edit profile
    [HttpGet]
    public async Task<IActionResult> EditProfile(string id)
    {
        try
        {
            if (string.IsNullOrEmpty(id)) return NotFound();
            var userDto = await _userService.FindUserByIdAsync(id);
            if (userDto is null) return NotFound();
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
    public async Task<IActionResult> EditProfile(UserViewModel viewModel)
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
