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
            new ApiScope("message.read", "Read Access to Message API"),
            new ApiScope("message.write", "Write Access to Message API"),
        };

    public static IEnumerable<ApiResource> ApiResources =>
            new[]
            {
                new ApiResource
                {
                    Name = "message",
                    DisplayName = "Message Api",
                    Description = "Allow the application to access Message Api on your behalf",
                    Scopes = new List<string> { "message.read", "message.write"},
                    ApiSecrets = new List<Secret> {new Secret("Wabase".Sha256())},
                    UserClaims = new List<string> {"role"}
                }
            };

    public static IEnumerable<Client> Clients =>
           new[]
           {
                /*new Client
                {
                    ClientId = "weatherApi",
                    ClientName = "ASP.NET Core Weather Api",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets = new List<Secret> {new Secret("Wabase".Sha256())},
                    AllowedScopes = new List<string> {"weatherApi.read"}
                },*/
                new Client
                {
                    ClientId = "oidcMVCApp",
                    ClientName = "Sample ASP.NET Core MVC Web App",
                    ClientSecrets = new List<Secret> {new Secret("Wabase".Sha256())},

                    AllowedGrantTypes = GrantTypes.Code,
                    RedirectUris = new List<string>
                    {
						"https://iproj.uz/signin-oidc",
                    },
                    FrontChannelLogoutUri = "https://iproj.uz/signout-oidc",
                    PostLogoutRedirectUris =
                    {
						"https://iproj.uz/signout-callback-oidc",
                    },
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "role",
                        "message.read",
                        "message.write"
                    },

                    RequirePkce = true,
                    AllowPlainTextPkce = false
                },

                new Client
                {
                    ClientId = "oidcMVCAppAdmin",
                    ClientName = "Sample ASP.NET Core MVC Web App Admin",
                    ClientSecrets = new List<Secret> {new Secret("Wabase".Sha256())},

                    AllowedGrantTypes = GrantTypes.Code,
                    RedirectUris = new List<string>
                    {
                        "https://admin.iproj.uz/signin-oidc",
                    },
                    FrontChannelLogoutUri = "https://admin.iproj.uz/signout-oidc",
                    PostLogoutRedirectUris =
                    {
                        "https://admin.iproj.uz/signout-callback-oidc",
                    },
                    AllowedScopes = new List<string>
                    {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        "role",
                        "message.write",
                        "message.write"
                    },

                    RequirePkce = true,
                    AllowPlainTextPkce = false
                }
           };
}
