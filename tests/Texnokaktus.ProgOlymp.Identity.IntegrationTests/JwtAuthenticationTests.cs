using System.Net;
using Microsoft.IdentityModel.Tokens;
using Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests;

[TestFixture]
public class JwtAuthenticationTests : SetupBase
{
    [Test]
    public async Task AcceptsRs256AndReturnsUserId()
    {
        using var response = await Client.GetWithBearerTokenAsync("/user", Tokens.Create());

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await response.Content.ReadAsStringAsync(), Is.EqualTo("42"));
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
            "foreign-key" => Tokens.Create(key: Tokens.OtherKey),
            "tampered" => TestJwtTokens.TamperWithPayload(Tokens.Create()),
            "hs256" => Tokens.Create(algorithm: SecurityAlgorithms.HmacSha256),
            "ps256" => Tokens.Create(algorithm: SecurityAlgorithms.RsaSsaPssSha256),
            "unsigned" => Tokens.Create(algorithm: SecurityAlgorithms.None),
            "issuer" => Tokens.Create(issuer: "untrusted-issuer"),
            "audience" => Tokens.Create(audience: "another-api"),
            "expired" => Tokens.Create(notBefore: DateTime.UtcNow.AddHours(-2), expires: DateTime.UtcNow.AddHours(-1)),
            "not-yet-valid" => Tokens.Create(notBefore: DateTime.UtcNow.AddHours(1), expires: DateTime.UtcNow.AddHours(2)),
            _ => throw new ArgumentOutOfRangeException(nameof(scenario))
        };
        using var response = await Client.GetWithBearerTokenAsync("/user", token);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task RejectsRequestWithoutBearerToken()
    {
        using var response = await Client.GetAsync("/user");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }
}
