using Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests;

[SetUpFixture]
public class SetupGlobal
{
    public static CustomWebApplicationFactory Factory { get; private set; } = null!;
    public static TestJwtTokens Tokens { get; private set; } = null!;
    private KeyFiles files = null!;

    [OneTimeSetUp]
    public void StartApplication()
    {
        Tokens = new TestJwtTokens();
        files = new KeyFiles();
        var publicKeyPath = files.WriteKey("public.pem", Tokens.SigningKey.ExportSubjectPublicKeyInfoPem());
        Factory = new CustomWebApplicationFactory(new Dictionary<string, string?>
        {
            ["JwtSettings:PublicKeyPath"] = publicKeyPath
        });
        // Start the shared application before any fixture runs.
        _ = Factory.Server;
    }

    [OneTimeTearDown]
    public async Task StopApplication()
    {
        try
        {
            if (Factory is not null)
                await Factory.DisposeAsync();
        }
        finally
        {
            files?.Dispose();
            Tokens?.Dispose();
        }
    }
}
