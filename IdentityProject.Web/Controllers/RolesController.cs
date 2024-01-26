using IdentityProject.Business.Interfaces.Features;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Common.Enums;
using IdentityProject.Web.Interfaces.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;
[Authorize(Roles = nameof(RoleType.Admin))]
public class RolesController(ILogger<RolesController> logger, IErrorController errorController, IRolesAccountManager rolesAccountManager, IIdentityManager identityManager) : Controller
{
    private readonly ILogger<RolesController> _logger = logger;
    private readonly IErrorController _errorController = errorController;
    private readonly IRolesAccountManager _rolesAccountManager = rolesAccountManager;
    private readonly IIdentityManager _identityManager = identityManager;

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
}