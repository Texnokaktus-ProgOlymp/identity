using System.Net.Http.Headers;

namespace Texnokaktus.ProgOlymp.Identity.IntegrationTests.Tools;

public static class JwtHttpClientExtensions
{
    public static async Task<HttpResponseMessage> GetWithBearerTokenAsync(
        this HttpClient client, string requestUri, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }
}
