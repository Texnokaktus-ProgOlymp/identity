using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

public sealed class TestJwtTokens : IDisposable
{
    public const string DefaultIssuer = "Texnokaktus.ProgOlymp.Api";
    public RSA SigningKey { get; } = RSA.Create(2048);
    public RSA OtherKey { get; } = RSA.Create(2048);

    public string Create(RSA? key = null, string algorithm = SecurityAlgorithms.RsaSha256,
                         string issuer = DefaultIssuer, string audience = DefaultIssuer,
                         DateTime? notBefore = null, DateTime? expires = null)
    {
        SecurityKey securityKey = algorithm == SecurityAlgorithms.HmacSha256
            ? new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32))
            : new RsaSecurityKey(key ?? SigningKey);
        var credentials = algorithm == SecurityAlgorithms.None ? null : new SigningCredentials(securityKey, algorithm);
        var token = new JwtSecurityToken(issuer, audience,
            [new Claim(JwtRegisteredClaimNames.Sub, "42"), new Claim(JwtRegisteredClaimNames.Name, "test-user")],
            notBefore ?? DateTime.UtcNow.AddMinutes(-1), expires ?? DateTime.UtcNow.AddMinutes(30), credentials);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string TamperWithPayload(string token)
    {
        var parts = token.Split('.');
        var payload = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[1]));
        parts[1] = Base64UrlEncoder.Encode(payload.Replace("42", "43", StringComparison.Ordinal));
        return string.Join('.', parts);
    }

    public void Dispose()
    {
        SigningKey.Dispose();
        OtherKey.Dispose();
    }
}
