using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Interfaces.Controllers;
public interface IErrorController
{
    IActionResult HandleException(Exception ex, string method, string? optionalMessage = null);
}