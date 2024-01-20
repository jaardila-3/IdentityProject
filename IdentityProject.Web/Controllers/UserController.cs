using System.Diagnostics;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Web.Models;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;

public class UserController(IIdentityManager identityManager) : Controller
{
    private readonly IIdentityManager _identityManager = identityManager;

    public IActionResult Index() => View();

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
}
