using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Texnokaktus.ProgOlymp.Identity.Extensions;

public static class HttpContextExtensions
{
    public static int GetUserId(this HttpContext context) => context.User.GetUserId();

    public static int GetUserId(this ClaimsPrincipal user) =>
        int.Parse(user.Claims.First(claim => claim.Type == ClaimTypes.NameIdentifier).Value);
}
