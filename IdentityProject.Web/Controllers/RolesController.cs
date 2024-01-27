using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services.Roles;
using IdentityProject.Common.Enums;
using IdentityProject.Web.Interfaces.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
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
        var roles = new List<Microsoft.AspNetCore.Identity.IdentityRole>();
        try
        {
            roles = await _rolesAccountManager.GetListAsync();
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(Index));
        }
        return View(roles);
    }

    [HttpGet]
    public IActionResult Create()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Create(IdentityRole role)
    {
        try
        {
            if (await _accountIdentityManager.RoleExistsAsync(role.Name!))
                return RedirectToAction(nameof(Index));

            var resultDto = await _accountIdentityManager.CreateRoleAsync(new IdentityRole(role.Name!));
            if (resultDto.Succeeded)
                return RedirectToAction(nameof(Index));

            _errorController.HandleErrors(resultDto.Errors);
            return View();
        }
        catch (Exception ex)
        {
            return _errorController.HandleException(ex, nameof(Index));
        }
    }
}