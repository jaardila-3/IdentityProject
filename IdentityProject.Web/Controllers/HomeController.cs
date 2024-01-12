using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using IdentityProject.Web.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace IdentityProject.Web.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly UserManager<IdentityUser> _userManager;

    public HomeController(ILogger<HomeController> logger, UserManager<IdentityUser> userManager)
    {
        _logger = logger;
        _userManager = userManager;
    }

    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            ViewData["IsTwoFactorAuthenticationActive"] = false;
        }
        else
        {
            ViewData["IsTwoFactorAuthenticationActive"] = user.TwoFactorEnabled;
        }
        return View();
    }
    
    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
