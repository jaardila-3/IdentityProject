using IdentityProject.Common.Enums;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace IdentityProject.Web.Controllers;
public class HomeController() : Controller
{
    [HttpGet]
    public IActionResult Index() => View();

    [HttpGet]
    public IActionResult Privacy() => View();

    [Authorize(Roles = nameof(RoleType.Admin))]
    [HttpGet]
    public IActionResult ProtectedView() => View();
}
