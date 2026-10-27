using Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests;

[NonParallelizable]
public abstract class SetupBase
{
    protected CustomWebApplicationFactory Factory => SetupGlobal.Factory;
    protected TestJwtTokens Tokens => SetupGlobal.Tokens;
    protected KeyFiles Files { get; private set; } = null!;
    protected HttpClient Client { get; private set; } = null!;
    private readonly List<HttpClient> clients = [];
    private readonly List<CustomWebApplicationFactory> applications = [];

    [SetUp]
    public void PrepareTest()
    {
        Files = new KeyFiles();
        Client = Factory.CreateClient();
        clients.Add(Client);
    }

    protected HttpClient CreateClient(IReadOnlyDictionary<string, string?> settings)
    {
        var application = new CustomWebApplicationFactory(settings);
        // Track the factory before starting it so failed startup is cleaned up too.
        applications.Add(application);
        var client = application.CreateClient();
        clients.Add(client);
        return client;
    }

    protected static Dictionary<string, string?> Settings(string path) => new()
    {
        ["JwtSettings:PublicKeyPath"] = path
    };

    [TearDown]
    public async Task CleanUpTest()
    {
        try
        {
            foreach (var client in clients)
                client.Dispose();
            clients.Clear();

            foreach (var application in applications)
                await application.DisposeAsync();
            applications.Clear();
        }
        finally
        {
            Files?.Dispose();
        }
    }
}
