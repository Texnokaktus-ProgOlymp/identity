using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Texnokaktus.ProgOlymp.Identity.Extensions;

public static class SecurityExtensions
{
    private const string DefaultClaimsIssuer = "Texnokaktus.ProgOlymp.Api";
    private const string DefaultAudience = "Texnokaktus.ProgOlymp.Api";

    public static AuthenticationBuilder AddConfiguredJwtBearer(
        this AuthenticationBuilder builder,
        IConfiguration configuration
    )
    {
        var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>() ?? new();
        var publicKey = LoadPublicKey(jwtSettings.PublicKeyPath);

        return builder.AddJwtBearer(options => options.TokenValidationParameters = new()
            {
                ValidIssuer = jwtSettings.ClaimsIssuer ?? DefaultClaimsIssuer,
                ValidAudience = jwtSettings.Audience ?? DefaultAudience,
                IssuerSigningKey = publicKey,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
            }
        );
    }

    private static RsaSecurityKey LoadPublicKey(string publicKeyPath)
    {
        if (string.IsNullOrWhiteSpace(publicKeyPath))
            throw new InvalidOperationException("JwtSettings:PublicKeyPath must not be empty.");

        string fullPath;
        string pem;
        try
        {
            fullPath = Path.GetFullPath(publicKeyPath, AppContext.BaseDirectory);
            pem = File.ReadAllText(fullPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
                                          or ArgumentException or NotSupportedException)
        {
            throw new InvalidOperationException(
                $"Unable to read the JWT public key file '{publicKeyPath}'. " +
                "Configure JwtSettings:PublicKeyPath or provide keys/jwt-public.pem relative to the application directory.",
                exception);
        }

        var contents = pem.AsSpan();
        if (!PemEncoding.TryFind(contents, out var fields)
            || !(contents[fields.Label].SequenceEqual("PUBLIC KEY")
                 || contents[fields.Label].SequenceEqual("RSA PUBLIC KEY"))
            || !contents[..fields.Location.Start].Trim().IsEmpty
            || !contents[fields.Location.End..].Trim().IsEmpty)
            throw new InvalidOperationException(
                $"The JWT public key file '{fullPath}' must contain exactly one PUBLIC KEY or RSA PUBLIC KEY PEM block.");

        using var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(contents);
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            throw new InvalidOperationException($"The JWT public key file '{fullPath}' does not contain a valid RSA public key.");
        }

        if (rsa.KeySize < 2048)
            throw new InvalidOperationException($"The JWT public key file '{fullPath}' must contain an RSA key of at least 2048 bits.");

        return new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false));
    }
}
