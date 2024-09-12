using IdentityModel;
using IdentityServer4.Test;
using Iproj.Models.Users;
using System.Security.Claims;

namespace Iproj.Services;

public class Users
{
    public static List<User> Get()
    {
        return new List<User>
            {
                new User
                {
                    Name = "Muhammadqodir",
                    Username = "muhammadqodir5050@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "muhammadqodir5050@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Owner"),
                        new Claim(JwtClaimTypes.PhoneNumber, "941092151"),
                    }
                },
                new User
                {
                    Name = "Able",
                    Username = "able.devops@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "able.devops@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "331092151"),
                    }
                },
                new User
                {
                    Name = "Samandarbek",
                    Username = "samandarbekyr@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "samandarbekyr@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "901234567"),
                    }
                },
                new User
                {
                    Name = "Samandar",
                    Username = "sharpistmaster@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "sharpistmaster@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "991234567"),
                    }
                },
                new User
                {
                    Name = "Behruz",
                    Username = "uzgrandmaster@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "uzgrandmaster@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "771234567"),
                    }
                },
                new User
                {
                    Name = "Olim",
                    Username = "olim@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "olim@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "661234567"),
                    }
                },
                new User
                {
                    Name = "Ada",
                    Username = "ada.lovelace@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "ada.lovelace@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "551234567"),
                    }
                },
                new User
                {
                    Name = "Charles",
                    Username = "charles.darwin@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "charles.darwin@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "441234567"),
                    }
                },
                new User
                {
                    Name = "Marie",
                    Username = "marie.curie@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "marie.curie@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "331234567"),
                    }
                },
                new User
                {
                    Name = "Albert",
                    Username = "albert.einstein@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "albert.einstein@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "221234567"),
                    }
                }
        };
    }
}
