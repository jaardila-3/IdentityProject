using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Interfaces.Controllers;
public interface IErrorController
{
    void HandleErrors(IEnumerable<string> errors);
    IActionResult HandleException(Exception ex, string method, string? optionalMessage = null);
}