# Project with AspNet Identity
In this project, I created a new application using the technology of **ASP.NET Identity** with **.NET Core 8** and **Code First**. Then, I used the following **dotnet CLI** commands and libraries to create it.

## Libraries

- dotnet add package Microsoft.EntityFrameworkCore.Tools --version 8.0.0
- dotnet add package Microsoft.EntityFrameworkCore.SqlServer --version 8.0.0
- dotnet add package Microsoft.EntityFrameworkCore --version 8.0.0
- dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version 8.0.0

## CLI Commands

### For creating and updating the project
- dotnet new sln
- dotnet new mvc
- dotnet new classlib
- dotnet sln add <file.csproj>
- dotnet add <file.csproj> reference <file.csproj>

### For migrations with Code First
- dotnet ef migrations add <name-new-migration>
- dotnet ef database update
