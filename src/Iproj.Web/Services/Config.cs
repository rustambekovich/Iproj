using IdentityServer4;
using IdentityServer4.Models;

namespace Iproj.Services;

public class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
              new[]
              {
                    new IdentityResources.OpenId(),
                    new IdentityResources.Profile(),
                    new IdentityResources.Email(),
                    new IdentityResource
                    {
                        Name = "role",
                        UserClaims = new List<string> {"role"}
                    }
              };

    public static IEnumerable<ApiScope> ApiScopes =>
        new[]
        {
            new ApiScope("weatherApi.read", "Read Access to Weather API"),
            new ApiScope("weatherApi.write", "Write Access to Weather API"),
        };

    public static IEnumerable<ApiResource> ApiResources =>
            new[]
            {
                new ApiResource
                {
                    Name = "weatherApi",
                    DisplayName = "Weather Api",
                    Description = "Allow the application to access Weather Api on your behalf",
                    Scopes = new List<string> { "weatherApi.read", "weatherApi.write"},
                    ApiSecrets = new List<Secret> {new Secret("Wabase".Sha256())},
                    UserClaims = new List<string> {"role"}
                }
            };

    public static IEnumerable<Client> Clients =>
           new[]
           {
                new Client
                {
                    ClientId = "weatherApi",
                    ClientName = "ASP.NET Core Weather Api",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = new List<Secret> {new Secret("Wabase".Sha256())},
                    AllowedScopes = new List<string> {"weatherApi.read"}
                },
                new Client
                {
                    ClientId = "oidcMVCApp",
                    ClientName = "Sample ASP.NET Core MVC Web App",
                    ClientSecrets = new List<Secret> {new Secret("Wabase".Sha256())},

                    AllowedGrantTypes = GrantTypes.Code,
                    RedirectUris = new List<string>
                    {
                        "http://192.168.0.52:5272/signin-oidc",
                    },
                    PostLogoutRedirectUris =
                    {
                        "http://localhost:5272/signout-callback-oidc",
                    },
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "role",
                        "weatherApi.read"
                    },

                    RequirePkce = true,
                    AllowPlainTextPkce = false
                }
           };
}
