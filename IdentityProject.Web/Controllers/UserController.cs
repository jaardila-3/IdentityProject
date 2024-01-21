using System.Diagnostics;
using IdentityProject.Business.Interfaces.Features;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Web.Models;
using IdentityProject.Web.Models.MapperExtensions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;

[Authorize]
public class UserController(IIdentityManager identityManager, IUserManager userManager) : Controller
{
    private readonly IIdentityManager _identityManager = identityManager;
    private readonly IUserManager _userManager = userManager;

    [HttpGet]
    public async Task<IActionResult> EditProfile(string id)
    {
        if (id is null)
            return NotFound();

        var userDto = await _userManager.FindByIdAsync(id);
        if (userDto is null)
            return NotFound();

        var viewModel = userDto.ToViewModel();

        return View(viewModel);
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
}
