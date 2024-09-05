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
                    Name = "Johndoe",
                    Username = "johndoe@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "johndoe@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "901234567"),
                    }
                },
                new User
                {
                    Name = "Janedoe",
                    Username = "janedoe@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "janedoe@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "991234567"),
                    }
                },
                new User
                {
                    Name = "William",
                    Username = "william.shakespeare@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "william.shakespeare@gmail.com"),
                        new Claim(JwtClaimTypes.Role, "Worker"),
                        new Claim(JwtClaimTypes.PhoneNumber, "771234567"),
                    }
                },
                new User
                {
                    Name = "Elon",
                    Username = "elon.musk@gmail.com",
                    Password = "12qwAS!@",
                    Claims = new List<Claim>
                    {
                        new Claim(JwtClaimTypes.Email, "elon.musk@gmail.com"),
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
