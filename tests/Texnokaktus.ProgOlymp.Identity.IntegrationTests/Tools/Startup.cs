using System.Globalization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Texnokaktus.ProgOlymp.Identity.Extensions;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

public class Startup(IConfiguration configuration)
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddConfiguredJwtBearer(configuration);
        services.AddAuthorization();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseEndpoints(endpoints => endpoints.MapGet("/user", context =>
            context.Response.WriteAsync(context.GetUserId().ToString(CultureInfo.InvariantCulture)))
            .RequireAuthorization());
    }
}
