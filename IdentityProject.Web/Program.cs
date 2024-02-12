using IdentityProject.Web.Interfaces.Controllers;
using IdentityProject.Web.Controllers;
using IdentityProject.Business;
using IdentityProject.Services;
using IdentityProject.DataAccess;
using IdentityProject.Common.Enums;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataAccessServices(builder.Configuration);
builder.Services.AddBusinessServices();
builder.Services.AddServices();

//configuration application cookie
builder.Services.ConfigureApplicationCookie(options =>
{
    // Cookie settings
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
});

//configuration policies
builder.Services.AddAuthorization(options =>
{
    //https://learn.microsoft.com/es-es/aspnet/core/security/authorization/roles?view=aspnetcore-8.0
    //[Authorize(Roles = "Administrator")] //Content("Administrator");
    //[Authorize(Roles = "HRManager,Finance")] //Content("HRManager || Finance");
    //[Authorize(Roles = "PowerUser")] [Authorize(Roles = "ControlPanelUser")] //Content("PowerUser && ControlPanelUser");

    //https://learn.microsoft.com/es-es/aspnet/core/security/authorization/policies?view=aspnetcore-8.0
    //[Authorize(Policy = "SuperUser")]
    options.AddPolicy("SuperUser", policy => policy.RequireUserName("jorge.ardilar").RequireRole(nameof(RoleType.Admin)));

    //https://learn.microsoft.com/es-es/aspnet/core/security/authorization/claims?view=aspnetcore-8.0
    //[Authorize(Policy = "AdminCreate")]
    options.AddPolicy("AdminCreate", policy => policy.RequireRole(nameof(RoleType.Admin)).RequireClaim("Create", "True"));
    //[Authorize(Policy = "AdminEditAndDelete")]
    options.AddPolicy("AdminEditAndDelete", policy => policy.RequireRole(nameof(RoleType.Admin)).RequireClaim("Edit", "True").RequireClaim("Delete", "True"));
});

//add IoC
//Scoped
builder.Services.AddScoped<IErrorController, ErrorController>();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
