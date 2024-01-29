using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Roles;
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
            return _errorController.HandleException(ex, nameof(Index));
        }
    }

    [HttpGet]
    public IActionResult Create() => View();

    [HttpPost]
    public async Task<IActionResult> Create(RoleViewModel viewModel)
    {
        if (!ModelState.IsValid) return View(viewModel);
        try
        {
            var createRoleResult = await _accountIdentityManager.CreateRoleAsync(viewModel.Name!);
            if (createRoleResult.Succeeded)
                return RedirectToAction(nameof(Index));

            _errorController.HandleErrors(createRoleResult.Errors);
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(Create));
        }
        return View(viewModel);
    }
}