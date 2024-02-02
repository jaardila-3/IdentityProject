using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;
public class HomeController() : Controller
{
    [HttpGet]
    public IActionResult Index() => View();

    [HttpGet]
    public IActionResult Privacy() => View();
}
