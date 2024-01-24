using IdentityProject.Web.Interfaces.Controllers;
using IdentityProject.Web.Controllers;
using IdentityProject.Business.identity;
using IdentityProject.Business.Services;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services;
using IdentityProject.Business.Interfaces.Features;
using IdentityProject.Business.Features.Users;
using IdentityProject.Services.SMTP.MailJet;
using IdentityProject.DataAccess.Persistence;
using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.DataAccess.Repositories.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        b => b.MigrationsAssembly("IdentityProject.Web"))); // this line is to Add Migrations in this project
                                                            // trustServerCertificate=true; this line in connection string is to resolve the trust server certificate error

//add identity service
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>().AddDefaultTokenProviders();

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

//configuration options for identity
builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings.
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 8;
    options.Password.RequiredUniqueChars = 1;
    //lockout settings.
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(60);
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;
    // User settings.
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;
});

//add IoC
//Transient
builder.Services.AddTransient<IIdentityManager, IdentityManager>();
builder.Services.AddTransient<IEmailService, EmailService>();
builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();
//Scoped
builder.Services.AddScoped<IErrorController, ErrorController>();
builder.Services.AddScoped<IUnitOfWork, UnitOfWorkIdentity>();
builder.Services.AddScoped(typeof(IRepositoryWriteCommands<>), typeof(RepositoryIdentity<>));
builder.Services.AddScoped<IUserAccountManager, UserAccountManager>();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
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
