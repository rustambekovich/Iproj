using IdentityModel;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.EntityFramework.Storage;
using Iproj.DataAccess;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace Iproj.Services;

public class SeedData
{
    public static void EnsureSeedData(string connectionString)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDbContext<IprojAspNetDbContext>(
            options => options.UseNpgsql(connectionString)
        );

        services
            .AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<IprojAspNetDbContext>()
            .AddDefaultTokenProviders();

        services.AddOperationalDbContext(
            options =>
            {
                options.ConfigureDbContext = db =>
                    db.UseNpgsql(
                        connectionString,
                        sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName)
                    );
            }
        );
        services.AddConfigurationDbContext(
            options =>
            {
                options.ConfigureDbContext = db =>
                    db.UseNpgsql(
                        connectionString,
                        sql => sql.MigrationsAssembly(typeof(SeedData).Assembly.FullName)
                    );
            }
        );

        var serviceProvider = services.BuildServiceProvider();

        using var scope = serviceProvider.GetRequiredService<IServiceScopeFactory>().CreateScope();
       /* scope.ServiceProvider.GetService<PersistedGrantDbContext>()!.Database.Migrate();

        var context = scope.ServiceProvider.GetService<ConfigurationDbContext>();
        context!.Database.Migrate();*/

        //EnsureSeedData(context);

        var ctx = scope.ServiceProvider.GetService<IprojAspNetDbContext>();
        ctx!.Database.Migrate();

        EnsureUsers(scope);
    }

    private static void EnsureUsers(IServiceScope scope)
    {
        var userMenenger = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

        var usersData = Users.Get();

        if (usersData != null && usersData.Count() > 0)
        {
            foreach(var user in usersData)
            {
                var userdata = userMenenger.FindByEmailAsync(user.Username).Result;

                if (userdata == null)
                {
                    userdata = new IdentityUser
                    {
                        UserName = user.Name,
                        Email = user.Username,
                        EmailConfirmed = true,
                    };

                    var result = userMenenger.CreateAsync(userdata, user.Password).Result;

                    if (!result.Succeeded)
                    {
                        throw new Exception(result.Errors.First().Description);
                    }

                    var userClaims = user.Claims.ToList();

                    if(userClaims != null && userClaims.Count() > 0)
                    {
                        result = userMenenger.AddClaimsAsync( userdata, userClaims).Result;

                        if (!result.Succeeded)
                        {
                            throw new Exception(result.Errors.First().Description);
                        }
                    }
                }
            }
        }
    }

    private static void EnsureSeedData(ConfigurationDbContext context)
    {
        if (!context.Clients.Any())
        {
            foreach (var client in Config.Clients.ToList())
            {
                context.Clients.Add(client.ToEntity());
            }

            context.SaveChanges();
        }

        if (!context.IdentityResources.Any())
        {
            foreach (var resource in Config.IdentityResources.ToList())
            {
                context.IdentityResources.Add(resource.ToEntity());
            }

            context.SaveChanges();
        }

        if (!context.ApiScopes.Any())
        {
            foreach (var resource in Config.ApiScopes.ToList())
            {
                context.ApiScopes.Add(resource.ToEntity());
            }

            context.SaveChanges();
        }

        if (!context.ApiResources.Any())
        {
            foreach (var resource in Config.ApiResources.ToList())
            {
                context.ApiResources.Add(resource.ToEntity());
            }

            context.SaveChanges();
        }
    }
}
