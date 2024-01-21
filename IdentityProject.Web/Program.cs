using IdentityProject.Business.identity;
using IdentityProject.Business.Services;
using IdentityProject.Business.Interfaces.Identity;
using IdentityProject.Business.Interfaces.Services;
using IdentityProject.Services.SMTP.MailJet;
using IdentityProject.DataAccess.Persistence;
using IdentityProject.DataAccess.Interfaces.Repositories;
using IdentityProject.DataAccess.Repositories.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using IdentityProject.Business.Interfaces.Features;
using IdentityProject.Business.Features.Users;

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
    options.AccessDeniedPath = new PathString("/Account/AccessDenied");
});

//configuration options for identity
builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings.
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    //lockout login
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
    //options user
    options.User.RequireUniqueEmail = true;
});

//add IoC
//Transient
builder.Services.AddTransient<IIdentityManager, IdentityManager>();
builder.Services.AddTransient<IEmailService, EmailService>();
builder.Services.AddTransient<IEmailSender, MailJetEmailSender>();
//Scoped
builder.Services.AddScoped<IUnitOfWork, UnitOfWorkIdentity>();
builder.Services.AddScoped(typeof(IRepositoryWriteCommands<>), typeof(RepositoryIdentity<>));
builder.Services.AddScoped<IUserManager, UserManager>();

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
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
