using System.Diagnostics;
using IdentityProject.Web.Interfaces.Controllers;
using IdentityProject.Web.Models;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Controllers;
public class ErrorController(ILogger<ErrorController> logger, IHttpContextAccessor httpContextAccessor) : Controller, IErrorController
{
    private readonly ILogger<ErrorController> _logger = logger;
    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() => View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });

    public void LogException(Exception ex, string method, string? errorMessage = null)
    {
        string? requestMethod = _httpContextAccessor.HttpContext?.Request.Method ?? string.Empty;
        _logger.LogError(ex, $"Error al procesar la solicitud {requestMethod} {method}: {(errorMessage is not null ? $"{errorMessage}" : $"{ex.Message}")}");
    }
}