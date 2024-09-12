using Iproj.DataAccess;
using Iproj.Services;
using Iproj.Services.Auth;
using Iproj.Web.Commons;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var assblyname = typeof(Program).Assembly.GetName().Name;

// Load Kestrel configuration from appsettings.json
/*builder.WebHost.UseKestrel(options =>
{
    options.Configure(builder.Configuration.GetSection("Kestrel"));
});*/

var defaultConnection = builder.Configuration.GetConnectionString("DefaultConnection");

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

	// Kirish sozlamalari (Login)
	options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(3);
	options.Lockout.MaxFailedAccessAttempts = 5;

	options.User.RequireUniqueEmail = true; 
})
	.AddEntityFrameworkStores<IprojAspNetDbContext>();

builder.Services.AddIdentityServer(options =>
{
    // Set the issuer URI to ensure all URLs are generated with HTTPS
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
    .AddInMemoryClients(Config.Clients)
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddInMemoryApiResources(Config.ApiResources)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddDeveloperSigningCredential();


builder.Services.AddMvc();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            /*options.LoginPath = "/Account/Login"; 
            options.AccessDeniedPath = "/Account/AccessDenied";*/
        });

builder.Services.AddAuthorization(options =>
{
    /*options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();*/
});

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
    /*endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Account}/{action=Login}/{id?}");*/
    endpoints.MapDefaultControllerRoute();
});


app.Run();
