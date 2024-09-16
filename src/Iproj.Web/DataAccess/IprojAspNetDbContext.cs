using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Iproj.DataAccess;

public class IprojAspNetDbContext : IdentityDbContext
{
    public IprojAspNetDbContext(DbContextOptions<IprojAspNetDbContext> options)
        : base(options)
    { }
}
