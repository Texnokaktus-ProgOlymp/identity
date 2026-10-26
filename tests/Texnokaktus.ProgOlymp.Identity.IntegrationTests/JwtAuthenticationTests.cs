using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Texnokaktus.ProgOlymp.Identity.Extensions;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests;

[TestFixture]
[NonParallelizable]
public class JwtAuthenticationTests
{
    private const string DefaultIssuer = "Texnokaktus.ProgOlymp.Api";
    private RSA signingKey = null!;
    private RSA otherKey = null!;
    private string directory = null!;
    private string publicKeyPath = null!;

    [OneTimeSetUp]
    public void CreateKeys()
    {
        signingKey = RSA.Create(2048);
        otherKey = RSA.Create(2048);
        directory = Path.Combine(AppContext.BaseDirectory, $"jwt-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        publicKeyPath = WriteKey("public.pem", signingKey.ExportSubjectPublicKeyInfoPem());
    }

    [OneTimeTearDown]
    public void DeleteKeys()
    {
        signingKey.Dispose();
        otherKey.Dispose();
        // Only files created by this fixture live in this unique directory.
        foreach (var file in Directory.EnumerateFiles(directory))
            File.Delete(file);
        Directory.Delete(directory);
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task AcceptsRs256AndReturnsUserId(bool pkcs1)
    {
        var path = WriteKey(pkcs1 ? "pkcs1.pem" : "spki.pem",
                            pkcs1 ? signingKey.ExportRSAPublicKeyPem() : signingKey.ExportSubjectPublicKeyInfoPem());
        await using var server = await CreateServer(Settings(path));
        using var client = server.GetTestClient();
        using var response = await SendToken(client, CreateToken());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await response.Content.ReadAsStringAsync(), Is.EqualTo("42"));
    }

    [TestCase("https://issuer.example", "custom-audience")]
    [TestCase(DefaultIssuer, DefaultIssuer)]
    public async Task AcceptsConfiguredIssuerAndAudience(string issuer, string audience)
    {
        var settings = Settings(publicKeyPath);
        settings["JwtSettings:ClaimsIssuer"] = issuer;
        settings["JwtSettings:Audience"] = audience;
        await using var server = await CreateServer(settings);
        using var client = server.GetTestClient();
        using var response = await SendToken(client, CreateToken(issuer: issuer, audience: audience));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task ResolvesRelativePathFromApplicationDirectory()
    {
        var relativePath = Path.GetRelativePath(AppContext.BaseDirectory, publicKeyPath);
        await using var server = await CreateServer(Settings(relativePath));
        using var client = server.GetTestClient();
        using var response = await SendToken(client, CreateToken());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task UsesDefaultPathWhenPathOrSectionIsMissing(bool sectionExists)
    {
        var defaultDirectory = Path.Combine(AppContext.BaseDirectory, "keys");
        var defaultPath = Path.Combine(defaultDirectory, "jwt-public.pem");
        var directoryExisted = Directory.Exists(defaultDirectory);
        Directory.CreateDirectory(defaultDirectory);
        // CreateNew prevents accidentally overwriting an existing deployment key.
        using (var file = new FileStream(defaultPath, FileMode.CreateNew, FileAccess.Write))
        using (var writer = new StreamWriter(file))
            writer.Write(signingKey.ExportSubjectPublicKeyInfoPem());

        try
        {
            var settings = new Dictionary<string, string?>();
            if (sectionExists)
                settings["JwtSettings:ClaimsIssuer"] = DefaultIssuer;
            await using var server = await CreateServer(settings);
            using var client = server.GetTestClient();
            using var response = await SendToken(client, CreateToken());

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
        finally
        {
            File.Delete(defaultPath);
            if (!directoryExisted)
                Directory.Delete(defaultDirectory);
        }
    }

    [Test]
    public async Task KeepsImportedKeyAfterFileIsDeleted()
    {
        var path = WriteKey("loaded-once.pem", signingKey.ExportSubjectPublicKeyInfoPem());
        await using var server = await CreateServer(Settings(path));
        File.Delete(path);
        using var client = server.GetTestClient();

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var response = await SendToken(client, CreateToken());
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
    }

    [TestCase("foreign-key")]
    [TestCase("tampered")]
    [TestCase("hs256")]
    [TestCase("ps256")]
    [TestCase("unsigned")]
    [TestCase("issuer")]
    [TestCase("audience")]
    [TestCase("expired")]
    [TestCase("not-yet-valid")]
    public async Task RejectsInvalidToken(string scenario)
    {
        var token = scenario switch
        {
            "foreign-key" => CreateToken(key: otherKey),
            "tampered" => TamperWithPayload(CreateToken()),
            "hs256" => CreateToken(algorithm: SecurityAlgorithms.HmacSha256),
            "ps256" => CreateToken(algorithm: SecurityAlgorithms.RsaSsaPssSha256),
            "unsigned" => CreateToken(algorithm: SecurityAlgorithms.None),
            "issuer" => CreateToken(issuer: "untrusted-issuer"),
            "audience" => CreateToken(audience: "another-api"),
            "expired" => CreateToken(notBefore: DateTime.UtcNow.AddHours(-2), expires: DateTime.UtcNow.AddHours(-1)),
            "not-yet-valid" => CreateToken(notBefore: DateTime.UtcNow.AddHours(1), expires: DateTime.UtcNow.AddHours(2)),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };
        await using var server = await CreateServer(Settings(publicKeyPath));
        using var client = server.GetTestClient();
        using var response = await SendToken(client, token);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task RejectsRequestWithoutBearerToken()
    {
        await using var server = await CreateServer(Settings(publicKeyPath));
        using var client = server.GetTestClient();
        using var response = await client.GetAsync("/user");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("\t")]
    public void RejectsEmptyPathAtRegistration(string path)
    {
        Assert.That(() => RegisterAuthentication(Settings(path)),
                    Throws.InvalidOperationException.With.Message.Contains("PublicKeyPath"));
    }

    [TestCase(false)]
    [TestCase(true)]
    public void RejectsUnreadableFileAtRegistration(bool directoryInsteadOfFile)
    {
        var path = directoryInsteadOfFile ? directory : Path.Combine(directory, "missing.pem");
        Assert.That(() => RegisterAuthentication(Settings(path)),
                    Throws.InvalidOperationException.With.Message.Contains("Unable to read"));
    }

    [TestCase("private-pkcs8")]
    [TestCase("private-pkcs1")]
    [TestCase("encrypted-private")]
    [TestCase("weak")]
    [TestCase("ec")]
    [TestCase("multiple")]
    [TestCase("mixed")]
    [TestCase("malformed")]
    [TestCase("invalid-rsa")]
    [TestCase("empty")]
    public void RejectsInvalidKeyAtRegistrationWithoutExposingContents(string scenario)
    {
        using var weakKey = RSA.Create(1024);
        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = scenario switch
        {
            "private-pkcs8" => signingKey.ExportPkcs8PrivateKeyPem(),
            "private-pkcs1" => signingKey.ExportRSAPrivateKeyPem(),
            "encrypted-private" => signingKey.ExportEncryptedPkcs8PrivateKeyPem("test-only-password",
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000)),
            "weak" => weakKey.ExportSubjectPublicKeyInfoPem(),
            "ec" => ecKey.ExportSubjectPublicKeyInfoPem(),
            "multiple" => signingKey.ExportSubjectPublicKeyInfoPem() + "\n" + otherKey.ExportRSAPublicKeyPem(),
            "mixed" => signingKey.ExportSubjectPublicKeyInfoPem() + "\n" + signingKey.ExportPkcs8PrivateKeyPem(),
            "malformed" => "-----BEGIN PUBLIC KEY-----\ninvalid!\n-----END PUBLIC KEY-----",
            "invalid-rsa" => PemEncoding.WriteString("PUBLIC KEY", [1, 2, 3]),
            "empty" => "",
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };
        var path = WriteKey(scenario + ".pem", pem);
        var exception = Assert.Throws<InvalidOperationException>(() => RegisterAuthentication(Settings(path)));

        Assert.That(exception!.Message, Does.Contain(path));
        if (pem.Length > 0)
            Assert.That(exception.ToString(), Does.Not.Contain(pem));
    }

    private string WriteKey(string filename, string pem)
    {
        var path = Path.Combine(directory, filename);
        File.WriteAllText(path, pem);
        return path;
    }

    private static Dictionary<string, string?> Settings(string path) => new()
    {
        ["JwtSettings:PublicKeyPath"] = path
    };

    private static void RegisterAuthentication(Dictionary<string, string?> settings)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        new ServiceCollection().AddAuthentication().AddConfiguredJwtBearer(configuration);
    }

    private static async Task<WebApplication> CreateServer(Dictionary<string, string?> settings)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            ContentRootPath = AppContext.BaseDirectory
        });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
               .AddConfiguredJwtBearer(configuration);
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/user", (HttpContext context) => context.GetUserId().ToString(CultureInfo.InvariantCulture))
           .RequireAuthorization();
        await app.StartAsync();
        return app;
    }

    private string CreateToken(RSA? key = null, string algorithm = SecurityAlgorithms.RsaSha256,
                               string issuer = DefaultIssuer, string audience = DefaultIssuer,
                               DateTime? notBefore = null, DateTime? expires = null)
    {
        SecurityKey securityKey = algorithm == SecurityAlgorithms.HmacSha256
            ? new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32))
            : new RsaSecurityKey(key ?? signingKey);
        var credentials = algorithm == SecurityAlgorithms.None ? null : new SigningCredentials(securityKey, algorithm);
        var token = new JwtSecurityToken(issuer, audience,
            [new Claim(JwtRegisteredClaimNames.Sub, "42"), new Claim(JwtRegisteredClaimNames.Name, "test-user")],
            notBefore ?? DateTime.UtcNow.AddMinutes(-1), expires ?? DateTime.UtcNow.AddMinutes(30), credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string TamperWithPayload(string token)
    {
        var parts = token.Split('.');
        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1]));
        parts[1] = Base64UrlEncoder.Encode(payload.Replace("42", "43", StringComparison.Ordinal));
        return string.Join('.', parts);
    }

    private static async Task<HttpResponseMessage> SendToken(HttpClient client, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/user");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }
}
