﻿using IdentityModel;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Iproj.Helpers;

public static class TokenExtensions
{
    public static ClaimsPrincipal DecodeJwtToken(this string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var identity = new ClaimsIdentity(jwtToken.Claims, "jwt");
        return new ClaimsPrincipal(identity);
    }

    public static string GetClaimValue(this ClaimsPrincipal claimsPrincipal, string claimType)
    {
        return claimsPrincipal?.Claims.FirstOrDefault(c => c.Type == claimType)?.Value!;
    }

    public static string GetRole(this ClaimsPrincipal user)
    {
        var roleClaim = user.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Role);
        return roleClaim?.Value!;
    }

    public static string GetSubId(this ClaimsPrincipal user)
    {
        var roleClaim = user.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject);
        return roleClaim?.Value!;
    }

    public static (string? Gmail, Guid? Id) GetEmailAndId(this string? subAndEmail)
    {

        if (subAndEmail != null)
        {
            var parts = subAndEmail.Split('|');

            if (parts.Length == 2)
            {
                string gmail = parts[1];
                var id = Guid.Parse(parts[0]);

                return (Gmail: gmail, Id: id);
            }
        }

        return (null, null);
    }

}
