using System.Net;
using System.Security.Cryptography;
using Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests;

[TestFixture]
public class JwtKeyConfigurationTests : SetupBase
{
    [TestCase(false)]
    [TestCase(true)]
    public async Task AcceptsPublicKeyPem(bool pkcs1)
    {
        var path = Files.WriteKey("public.pem", pkcs1
            ? Tokens.SigningKey.ExportRSAPublicKeyPem()
            : Tokens.SigningKey.ExportSubjectPublicKeyInfoPem());
        var client = CreateClient(Settings(path));
        using var response = await client.GetWithBearerTokenAsync("/user", Tokens.Create());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await response.Content.ReadAsStringAsync(), Is.EqualTo("42"));
    }

    [TestCase("https://issuer.example", "custom-audience")]
    [TestCase(TestJwtTokens.DefaultIssuer, TestJwtTokens.DefaultIssuer)]
    public async Task AcceptsConfiguredIssuerAndAudience(string issuer, string audience)
    {
        var path = Files.WriteKey("public.pem", Tokens.SigningKey.ExportSubjectPublicKeyInfoPem());
        var settings = Settings(path);
        settings["JwtSettings:ClaimsIssuer"] = issuer;
        settings["JwtSettings:Audience"] = audience;
        var client = CreateClient(settings);
        using var response = await client.GetWithBearerTokenAsync("/user", Tokens.Create(issuer: issuer, audience: audience));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task ResolvesRelativePathFromApplicationDirectory()
    {
        var path = Files.WriteKey("public.pem", Tokens.SigningKey.ExportSubjectPublicKeyInfoPem());
        var client = CreateClient(Settings(Path.GetRelativePath(AppContext.BaseDirectory, path)));
        using var response = await client.GetWithBearerTokenAsync("/user", Tokens.Create());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [TestCase(false)]
    [TestCase(true)]
    public async Task UsesDefaultPathWhenPathOrSectionIsMissing(bool sectionExists)
    {
        Files.WriteDefaultKey(Tokens.SigningKey.ExportSubjectPublicKeyInfoPem());
        var settings = new Dictionary<string, string?>();
        if (sectionExists)
            settings["JwtSettings:ClaimsIssuer"] = TestJwtTokens.DefaultIssuer;
        var client = CreateClient(settings);
        using var response = await client.GetWithBearerTokenAsync("/user", Tokens.Create());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task KeepsImportedKeyAfterFileIsDeleted()
    {
        var path = Files.WriteKey("public.pem", Tokens.SigningKey.ExportSubjectPublicKeyInfoPem());
        var client = CreateClient(Settings(path));
        File.Delete(path);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            using var response = await client.GetWithBearerTokenAsync("/user", Tokens.Create());
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
    }

    [TestCase("")]
    [TestCase(" ")]
    [TestCase("\t")]
    public void RejectsEmptyPathAtStartup(string path)
    {
        Assert.That(() => CreateClient(Settings(path)),
                    Throws.InvalidOperationException.With.Message.Contains("PublicKeyPath"));
    }

    [TestCase(false)]
    [TestCase(true)]
    public void RejectsUnreadableFileAtStartup(bool directoryInsteadOfFile)
    {
        var path = directoryInsteadOfFile ? Files.DirectoryPath : Path.Combine(Files.DirectoryPath, "missing.pem");
        Assert.That(() => CreateClient(Settings(path)),
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
    public void RejectsInvalidKeyAtStartupWithoutExposingContents(string scenario)
    {
        using var weakKey = RSA.Create(1024);
        using var ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pem = scenario switch
        {
            "private-pkcs8" => Tokens.SigningKey.ExportPkcs8PrivateKeyPem(),
            "private-pkcs1" => Tokens.SigningKey.ExportRSAPrivateKeyPem(),
            "encrypted-private" => Tokens.SigningKey.ExportEncryptedPkcs8PrivateKeyPem("test-only-password",
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000)),
            "weak" => weakKey.ExportSubjectPublicKeyInfoPem(),
            "ec" => ecKey.ExportSubjectPublicKeyInfoPem(),
            "multiple" => Tokens.SigningKey.ExportSubjectPublicKeyInfoPem() + "\n" + Tokens.OtherKey.ExportRSAPublicKeyPem(),
            "mixed" => Tokens.SigningKey.ExportSubjectPublicKeyInfoPem() + "\n" + Tokens.SigningKey.ExportPkcs8PrivateKeyPem(),
            "malformed" => "-----BEGIN PUBLIC KEY-----\ninvalid!\n-----END PUBLIC KEY-----",
            "invalid-rsa" => PemEncoding.WriteString("PUBLIC KEY", [1, 2, 3]),
            "empty" => "",
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };
        var path = Files.WriteKey("invalid.pem", pem);
        var exception = Assert.Throws<InvalidOperationException>(() => CreateClient(Settings(path)));

        Assert.That(exception!.Message, Does.Contain(path));
        if (pem.Length > 0)
            Assert.That(exception.ToString(), Does.Not.Contain(pem));
    }
}
