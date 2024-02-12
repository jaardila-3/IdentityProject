using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;
public class HomeController() : Controller
{
    [HttpGet]
    public IActionResult Index() => View();

    [HttpGet]
    [Authorize(Policy = "SuperUser")]
    public IActionResult Privacy() => View();
}
