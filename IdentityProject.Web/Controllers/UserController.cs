using System.Security.Claims;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Roles;
using IdentityProject.Business.Interfaces.Services.Users;
using IdentityProject.Common.Enums;
using IdentityProject.Web.Claims;
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
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> Index()
    {
        try
        {
            var users = await _userService.GetListUsersAsync() ?? [];
            var viewModel = users.Select(u => u.ToViewModel()).ToList();
            return View(viewModel);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Index));
            throw;
        }
    }

    #region Edit User
    [HttpGet]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> Edit(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        try
        {
            var userDto = await _userService.FindUserByIdAsync(id);
            if (userDto is null) return NotFound();
            var viewModel = userDto!.ToViewModel();
            return View(viewModel);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Edit));
            throw;
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> Edit(UserViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            try
            {
                var userDto = viewModel.ToDto();
                var updateUserResult = await _accountIdentityManager.UpdateUserAsync(userDto);
                if (updateUserResult.Succeeded)
                {
                    TempData["Success"] = "datos actualizados correctamente";
                    return RedirectToAction(nameof(HomeController.Index));
                }

                foreach (var error in updateUserResult.Errors) ModelState.AddModelError(string.Empty, error);
            }
            catch (Exception ex)
            {
                _errorController.LogException(ex, nameof(Edit));
                throw;
            }
        }
        return View(viewModel);
    }

    [HttpGet]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> AssignRoles(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        try
        {
            var user = await _userService.FindUserByIdAsync(id); ;
            if (user is null) return NotFound();
            var viewModel = user.ToViewModel();

            var userRoles = await _rolesService.GetUserRolesByUserIdAsync(id) ?? [];
            var rolesApp = await _rolesService.GetListRolesAsync() ?? [];

            var currentRoles = rolesApp.Where(r => userRoles.Any(ur => ur.RoleId == r.Id)).ToList() ?? [];
            var unassignedRoles = rolesApp.Where(r => !userRoles.Any(ur => ur.RoleId == r.Id)).ToList() ?? [];

            viewModel.RolesApp = unassignedRoles.Select(r => new SelectListItem { Value = r.Id, Text = r.Name }).ToList() ?? [];
            viewModel.CurrentRoles = currentRoles.Select(r => new RoleViewModel { Id = r.Id, Name = r.Name }).ToList() ?? [];
            return View(viewModel);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(AssignRoles));
            throw;
        }
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> AssignRoles(UserViewModel viewModel)
    {
        if (string.IsNullOrEmpty(viewModel.RoleId)) ModelState.AddModelError(nameof(viewModel.RoleId), "No se ha seleccionado un rol");
        try
        {
            if (ModelState.IsValid)
            {
                var userRoleToRemoveResult = await _accountIdentityManager.AssignNewUserRoleAsync(viewModel.Id!, viewModel.RoleId!);
                if (userRoleToRemoveResult.Succeeded)
                {
                    TempData["Success"] = "Nuevo rol asignado correctamente al usuario";
                    return RedirectToAction(nameof(AssignRoles), new { id = viewModel.Id });
                }
                foreach (var error in userRoleToRemoveResult.Errors) ModelState.AddModelError(string.Empty, error);
            }
            var userRoles = await _rolesService.GetUserRolesByUserIdAsync(viewModel.Id!) ?? [];
            var rolesApp = await _rolesService.GetListRolesAsync() ?? [];
            var currentRoles = rolesApp.Where(r => userRoles.Any(ur => ur.RoleId == r.Id)).ToList() ?? [];
            var unassignedRoles = rolesApp.Where(r => !userRoles.Any(ur => ur.RoleId == r.Id)).ToList() ?? [];
            viewModel.RolesApp = unassignedRoles.Select(r => new SelectListItem { Value = r.Id, Text = r.Name }).ToList() ?? [];
            viewModel.CurrentRoles = currentRoles.Select(r => new RoleViewModel { Id = r.Id, Name = r.Name }).ToList() ?? [];
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(AssignRoles));
            throw;
        }
        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> RemoveUserRole(string roleId, string userId)
    {
        if (string.IsNullOrEmpty(roleId) || string.IsNullOrEmpty(userId)) return NotFound();
        try
        {
            var userRoleToRemoveResult = await _accountIdentityManager.RemoveUserRoleAsync(userId, roleId);
            if (userRoleToRemoveResult.Succeeded)
            {
                TempData["Success"] = "El rol del usuario fue eliminado correctamente";
                return RedirectToAction(nameof(AssignRoles), new { id = userId });
            }
            TempData["Error"] = userRoleToRemoveResult.Errors.FirstOrDefault();
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(RemoveUserRole));
            throw;
        }
        return RedirectToAction(nameof(AssignRoles), new { id = userId });
    }
    #endregion

    #region Claims
    [HttpGet]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> ManageUserClaims(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        var viewModel = new UserClaimsViewModel() { UserId = id };
        try
        {
            var userClaims = await _accountIdentityManager.GetRemoveOrAssignUserClaimsByIdAsync(id);
            foreach (Claim item in ClaimsManager.ClaimsCollection)
            {
                ClaimApp claimApp = new() { ClaimType = item.Type };
                if (userClaims.Any(c => c.Type == item.Type)) claimApp.Selected = true;
                viewModel.Claims.Add(claimApp);
            }
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(ManageUserClaims));
            throw;
        }
        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> ManageUserClaims(UserClaimsViewModel viewModel)
    {
        if (ModelState.IsValid)
        {
            bool removeClaims = true;
            var assignClaimsSelected = viewModel.Claims.Where(c => c.Selected).Select(c => new Claim(c.ClaimType!, c.Selected.ToString()));
            var noPermissionsSelected = viewModel.Claims.All(c => !c.Selected); // In case the user did not select any permissions 
            try
            {
                var userClaims = await _accountIdentityManager.GetRemoveOrAssignUserClaimsByIdAsync(viewModel.UserId!, removeClaims, assignClaimsSelected);
                if (userClaims.Any() || noPermissionsSelected)
                {
                    TempData["Success"] = "permisos actualizados correctamente";
                    return RedirectToAction(nameof(Index));
                }
            }
            catch (Exception ex)
            {
                _errorController.LogException(ex, nameof(ManageUserClaims));
                throw;
            }
            ModelState.AddModelError(string.Empty, "No se actualizaron los permisos, vuelve a intentarlo.");
        }
        return View(viewModel);
    }
    #endregion

    #region Lock and Unlock
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> Lock(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        var endDate = DateTimeOffset.UtcNow.AddYears(1);
        try
        {
            var lockUserResult = await _accountIdentityManager.LockAndUnlockUserAsync(id, endDate);
            if (lockUserResult.Succeeded) TempData["Success"] = "Usuario bloqueado correctamente";
            else TempData["Error"] = lockUserResult.Errors.FirstOrDefault();
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Lock));
            throw;
        }
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> Unlock(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        try
        {
            var lockUserResult = await _accountIdentityManager.LockAndUnlockUserAsync(id);
            if (lockUserResult.Succeeded) TempData["Success"] = "Usuario desbloqueado correctamente";
            else TempData["Error"] = lockUserResult.Errors.FirstOrDefault();
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Unlock));
            throw;
        }
        return RedirectToAction(nameof(Index));
    }
    #endregion

    #region delete user
    [HttpPost]
    [ValidateAntiForgeryToken]
    [Authorize(Roles = RoleTypeString.Administrator)]
    public async Task<IActionResult> Delete(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        try
        {
            var deleteUserResult = await _accountIdentityManager.DeleteUserAsync(id);
            if (deleteUserResult.Succeeded) TempData["Success"] = "Usuario eliminado correctamente";
            else TempData["Error"] = deleteUserResult.Errors.FirstOrDefault();
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Delete));
            throw;
        }
        return RedirectToAction(nameof(Index));
    }
    #endregion

    #region Edit profile
    [HttpGet]
    public async Task<IActionResult> EditProfile(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        try
        {
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
