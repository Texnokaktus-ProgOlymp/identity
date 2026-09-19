namespace Texnokaktus.ProgOlymp.Identity;

internal class JwtSettings
{
    public string? ClaimsIssuer { get; init; }
    public string? Audience { get; init; }
    public string? IssuerSigningKey { get; init; }
}
