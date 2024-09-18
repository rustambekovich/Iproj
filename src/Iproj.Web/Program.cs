using IdentityServer4.Models;
using Iproj.DataAccess;
using Iproj.Services;
using Iproj.Services.Auth;
using Iproj.Web.Commons;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);

var assblyname = typeof(Program).Assembly.GetName().Name;

var defaultConnection = builder.Configuration.GetConnectionString("DefaultConnection");

// save project migration
builder.Services.AddDbContext<IprojAspNetDbContext>(options =>
    options.UseNpgsql(defaultConnection,
    d => d.MigrationsAssembly(assblyname)));

builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
	options.Password.RequireDigit = false; 
	options.Password.RequireLowercase = false; 
	options.Password.RequireUppercase = false; 
	options.Password.RequireNonAlphanumeric = false; 
	options.Password.RequiredLength = 4; 
	options.Password.RequiredUniqueChars = 0; 

	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(3);
	options.Lockout.MaxFailedAccessAttempts = 5;

	options.User.RequireUniqueEmail = true; 
})
	.AddEntityFrameworkStores<IprojAspNetDbContext>();

var clients = builder.Configuration.GetSection("IdentityServer:Clients").Get<List<Client>>();
var identityResources = builder.Configuration.GetSection("IdentityServer:IdentityResources").Get<List<IdentityResource>>();
var apiScopes = builder.Configuration.GetSection("IdentityServer:ApiScopes").Get<List<ApiScope>>();
var apiResources = builder.Configuration.GetSection("IdentityServer:ApiResources").Get<List<ApiResource>>();

builder.Services.AddIdentityServer(options =>
{
    options.IssuerUri = "https://auth.iproj.uz";
    
}).AddConfigurationStore(options =>
    {
        options.ConfigureDbContext = d =>
        d.UseNpgsql(defaultConnection, opt => opt.MigrationsAssembly(assblyname));
    })
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = d =>
        d.UseNpgsql(defaultConnection, opt => opt.MigrationsAssembly(assblyname));
    })
    .AddInMemoryClients(clients)
    .AddInMemoryIdentityResources(identityResources)
    .AddInMemoryApiResources(apiResources)
    .AddInMemoryApiScopes(apiScopes)
    .AddDeveloperSigningCredential();


builder.Services.AddMvc();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddControllersWithViews();
builder.Services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie();

builder.Services.AddAuthorization();

var app = builder.Build();

app.Use((context, next) =>
{
    context.Request.Scheme = "https"; return next();
});

//app.UseMiddleware<RateLimitingMiddleware>();

//app.ApplyMigrations();

app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseIdentityServer();

SeedData.EnsureSeedData(defaultConnection!);

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();
