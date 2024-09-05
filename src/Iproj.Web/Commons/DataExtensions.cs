using IdentityServer4.EntityFramework.DbContexts;
using Iproj.DataAccess;
using Microsoft.EntityFrameworkCore;

namespace Iproj.Web.Commons;

public static class DataExtensions
{
    public static void ApplyMigrations(this WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            // 1. PersistedGrantDbContext migration
            var persistedGrantDbContext = scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>();
            persistedGrantDbContext.Database.Migrate();

            // 2. ConfigurationDbContext migration
            var configurationDbContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
            configurationDbContext.Database.Migrate();

            // 3. IprojAspNetDbContext migration
            var aspNetDbContext = scope.ServiceProvider.GetRequiredService<IprojAspNetDbContext>();
            aspNetDbContext.Database.Migrate();
        }
    }
}
