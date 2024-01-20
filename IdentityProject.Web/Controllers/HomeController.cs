using System.Diagnostics;
using IdentityProject.Web.Models;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Common.Enums;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace IdentityProject.Web.Controllers;

public class HomeController(IIdentityManager identityManager) : Controller
{
    private readonly IIdentityManager _identityManager = identityManager;

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var user = await _identityManager.GetUserAsync(User);

        if (user is null)
            ViewData["IsTwoFactorAuthenticationActive"] = false;
        else
            ViewData["IsTwoFactorAuthenticationActive"] = user.TwoFactorEnabled;

        return View();
    }

    [HttpGet]
    public IActionResult Privacy() => View();

    [Authorize(Roles = nameof(RoleType.Admin))]
    [HttpGet]
    public IActionResult ProtectedView() => View();

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
}
