using Microsoft.AspNetCore.Mvc;

namespace IdentityProject.Web.Interfaces.Controllers;
public interface IErrorController
{
    void LogException(Exception ex, string method, string? errorMessage = null);
}