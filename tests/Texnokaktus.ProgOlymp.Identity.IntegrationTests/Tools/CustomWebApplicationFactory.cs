using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

public class CustomWebApplicationFactory(IReadOnlyDictionary<string, string?> settings)
    : WebApplicationFactory<Startup>
{
    // Supply a host explicitly: this assembly's entry point belongs to NUnit/MTP.
    protected override IHostBuilder CreateHostBuilder() => new HostBuilder()
        .ConfigureWebHost(builder => builder.UseStartup<Startup>());

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseContentRoot(AppContext.BaseDirectory);
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.Sources.Clear();
            configuration.AddInMemoryCollection(settings);
        });
        builder.ConfigureLogging(logging =>
        {
            logging.ClearProviders();
            logging.AddSimpleConsole();
            logging.SetMinimumLevel(LogLevel.Warning);
        });
    }
}
