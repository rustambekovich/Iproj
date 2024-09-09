using AutoMapper;
using Iproj.DataAccess;
using Iproj.Services;
using Iproj.Services.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Iproj.Web.Commons;

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

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
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
    /*.AddInMemoryApiResources(Config.ApiResources)
    .AddInMemoryApiScopes(Config.ApiScopes)*/
    .AddDeveloperSigningCredential();


builder.Services.AddMvc();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.Use((context, next) => 
{ 
    context.Request.Scheme = "https"; return next(); 
});

app.ApplyMigrations();

app.UseStaticFiles();
app.UseRouting();
app.UseIdentityServer();
SeedData.EnsureSeedData(defaultConnection!);

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});


app.Run();
