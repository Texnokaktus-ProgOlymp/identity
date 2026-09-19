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
        var jwtSettings = configuration.GetSection("JwtSettings").Get<JwtSettings>()
                       ?? throw new("No JwtSettings in the configuration");

        var issuerSigningKeyBase64 = jwtSettings.IssuerSigningKey
                                  ?? throw new("No IssuerSigningKey in the JwtSettings");

        return builder.AddJwtBearer(options => options.TokenValidationParameters = new()
            {
                ValidIssuer = jwtSettings.ClaimsIssuer ?? DefaultClaimsIssuer,
                ValidAudience = jwtSettings.Audience ?? DefaultAudience,
                IssuerSigningKey = new SymmetricSecurityKey(
                    Convert.FromBase64String(
                        issuerSigningKeyBase64
                    )
                )
            }
        );
    }
}
