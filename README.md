# Project with AspNet Identity

In this project, I created a new application using the technology of **ASP.NET Identity** with **.NET Core 8** and **Code First**. Then, I used the following **dotnet CLI** commands and libraries to create it.

## General Libraries

- dotnet add package Microsoft.EntityFrameworkCore.Tools --version 8.0.0
- dotnet add package Microsoft.EntityFrameworkCore.SqlServer --version 8.0.0
- dotnet add package Microsoft.EntityFrameworkCore --version 8.0.0
- dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version 8.0.0

## Email Libraries

- dotnet add package Microsoft.AspNetCore.Identity.UI --version 8.0.0
- dotnet add package Microsoft.Extensions.Configuration.Abstractions --version 8.0.0
- dotnet add package Mailjet.Api --version 1.2.3 (to use this version)

## CLI Commands

### For creating and updating the project

- dotnet new sln
- dotnet new mvc
- dotnet new classlib
- dotnet sln add <file.csproj>
- dotnet add <file.csproj> reference <file.csproj>

### For execute the project

- dotnet build
- dotnet watch run --project <file.csproj>

### For migrations with Code First

- dotnet ef migrations add <name-new-migration>
- dotnet ef migrations add <name-new-migration> --project <path-name-project>
- dotnet ef migrations remove
- dotnet ef database update

## Fonts for QR code

- https://learn.microsoft.com/es-es/aspnet/core/security/authentication/identity-enable-qrcodes?view=aspnetcore-8.0
- https://learn.microsoft.com/es-es/aspnet/core/security/authentication/identity-enable-qrcodes?view=aspnetcore-8.0
