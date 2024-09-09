using System.Threading.RateLimiting;
namespace Iproj.Web.Services.Commons;

public class RateLimitingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TokenBucketRateLimiter _rateLimiter;

    public RateLimitingMiddleware(RequestDelegate next)
    {
        _next = next;

        // Define the rate limiter configuration
        _rateLimiter = new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
        {
            TokenLimit = 3, // Total number of tokens 
            TokensPerPeriod = 3, 
            ReplenishmentPeriod = TimeSpan.FromSeconds(10), 
            AutoReplenishment = true 
        });
    }

    public async Task Invoke(HttpContext context)
    {
        var lease = await _rateLimiter.AcquireAsync(1);

        if (lease.IsAcquired)
        {
            await _next(context); 
        }
        else
        {
            context.Response.StatusCode = 429; // HTTP 429 Too Many Requests
            await context.Response.WriteAsync("Rate limit exceeded");
        }
    }
}

