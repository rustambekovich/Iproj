using Iproj.DataAccess;
using Iproj.Services;
using Iproj.Services.Auth;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

var assblyname = typeof(Program).Assembly.GetName().Name;

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

app.MapControllers();

app.Run();
