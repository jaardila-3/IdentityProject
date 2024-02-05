using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Roles;
using IdentityProject.Common.Dto;
using IdentityProject.Common.Enums;
using IdentityProject.Web.Interfaces.Controllers;
using IdentityProject.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;
[Authorize(Roles = nameof(RoleType.Admin))]
public class RolesController(IErrorController errorController, IRolesService rolesAccountManager, IAccountIdentityManager accountIdentityManager) : Controller
{
    private readonly IErrorController _errorController = errorController;
    private readonly IRolesService _rolesAccountManager = rolesAccountManager;
    private readonly IAccountIdentityManager _accountIdentityManager = accountIdentityManager;

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        try
        {
            var roles = await _rolesAccountManager.GetListAsync() ?? [];
            var viewModel = roles.Select(r => new RoleViewModel { Id = r.Id, Name = r.Name }).ToList();
            return View(viewModel);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Index));
            throw;
        }
    }

    [HttpGet]
    public IActionResult Create() => View();

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(RoleViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        try
        {
            var createRoleResult = await _accountIdentityManager.CreateRoleAsync(viewModel.Name!);
            if (createRoleResult.Succeeded)
                return RedirectToAction(nameof(Index));

            foreach (var error in createRoleResult.Errors) ModelState.AddModelError(string.Empty, error);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Create));
            throw;
        }
        return View(viewModel);
    }

    [HttpGet]
    public async Task<IActionResult> Edit(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        RoleDto? role = null;
        try
        {
            role = await _rolesAccountManager.GetByIdAsync(id);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Edit));
            throw;
        }
        if (role is null) return RedirectToAction(nameof(Index));
        var viewModel = new RoleViewModel { Id = role.Id, Name = role.Name };
        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Edit(RoleViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        try
        {
            var updateRoleResult = await _accountIdentityManager.UpdateRoleAsync(new RoleDto(viewModel.Id, viewModel.Name));
            if (updateRoleResult.Succeeded)
                return RedirectToAction(nameof(Index));

            foreach (var error in updateRoleResult.Errors) ModelState.AddModelError(string.Empty, error);
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Edit));
            throw;
        }
        return View(viewModel);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(string id)
    {
        if (string.IsNullOrEmpty(id)) return NotFound();
        try
        {
            var deleteRoleResult = await _accountIdentityManager.DeleteRoleAsync(id);
            if (deleteRoleResult.Succeeded) return RedirectToAction(nameof(Index));
        }
        catch (Exception ex)
        {
            _errorController.LogException(ex, nameof(Delete));
            throw;
        }
        return RedirectToAction(nameof(HomeController.Index), "Home");
    }
}