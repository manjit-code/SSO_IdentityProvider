using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SSO_IdentityProvider.API.DTOs;
using SSO_IdentityProvider.Application.Services;
using SSO_IdentityProvider.Domain.Entities.OAuth;

namespace SSO_IdentityProvider.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OAuthController : ControllerBase
    {
        private readonly OAuthService _oauthService;

        public OAuthController(OAuthService oauthService)
        {
            _oauthService = oauthService;
        }

        [HttpPost("authorize")]
        public IActionResult Authorize([FromQuery] string client_id, [FromQuery] string redirect_uri, [FromQuery] string username, [FromQuery] string code_challenge, [FromQuery] string code_challenge_method = "S256")
        {
            if (string.IsNullOrWhiteSpace(username)) throw new UnauthorizedAccessException("Authenticated username required");

            // user already authenticated by client
            var code = _oauthService.GenerateAuthorizationCode(client_id, redirect_uri, username, code_challenge, code_challenge_method);

            return Ok(new { code });
        }

        [HttpPost("token")]

        [Consumes("application/x-www-form-urlencoded")] // MUST support application/x-www-form-urlencoded for token requests.
        public IActionResult Token([FromForm] string grant_type, [FromForm] string? code, [FromForm] string client_id, [FromForm] string? redirect_uri, [FromForm] string? code_verifier, [FromForm] string? refresh_token)
        {
            return grant_type switch
            {
                "authorization_code" => HandleAuthorizationCodeGrant(client_id, code!, redirect_uri!, code_verifier!),

                "refresh_token" => HandleRefreshTokenGrant(client_id, refresh_token!),

                _ => BadRequest("Unsupported grant_type")
            };
        }

        private IActionResult HandleAuthorizationCodeGrant(string clientId, string code, string redirectUri, string codeVerifier)
        {
            var result = _oauthService.ExchangeCodeForToken(code, clientId, redirectUri, codeVerifier);

            return Ok(new
            {
                access_token = result.accessToken,
                refresh_token = result.refreshToken,
                token_type = "Bearer",
                expires_in = 3600
            });
        }

        private IActionResult HandleRefreshTokenGrant(string clientId, string refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken)) return BadRequest("refresh_token is required");

            // IMPORTANT: Decode once at boundary
            var decodedRefreshToken = Uri.UnescapeDataString(refreshToken);

            var result = _oauthService.RefreshAccessToken(decodedRefreshToken, clientId);

            return Ok(new
            {
                access_token = result.accessToken,
                refresh_token = result.refreshToken,
                token_type = "Bearer",
                expires_in = 3600
            });
        }


        [HttpPost("revoke")]
        public IActionResult Revoke([FromForm] string token, [FromForm] string token_type_hint = "refresh_token")
        {
            if (token_type_hint != "refresh_token") return BadRequest("Unsupported token type");

            if (string.IsNullOrWhiteSpace(token))
                return Ok(); // OAuth spec: still return 200

            // Decode refresh token safely
            var decodedToken = Uri.UnescapeDataString(token);

            _oauthService.RevokeRefreshToken(decodedToken);

            // OAuth spec: return 200 even if token was invalid
            return Ok();
        }

        [Authorize]
        [HttpPost("logout-all")]
        public IActionResult LogoutAll()
        {
            var username = User.Identity?.Name;
            if (string.IsNullOrWhiteSpace(username)) return Unauthorized();

            _oauthService.LogoutEverywhere(username);

            return NoContent();
        }

        [Authorize]
        [HttpGet("userinfo")]
        public async Task<IActionResult> UserInfo([FromServices] DirectoryService directoryService)
        {
            var username = User.Identity?.Name;
            if (string.IsNullOrWhiteSpace(username)) return Unauthorized();

            var user = await directoryService.GetUserInfoAsync(username);

            var response = new UserInfoResponse
            {
                Sub = username,
                PreferredUsername = username,
                Name = user.DisplayName,
                Email = user.Email,
                PhoneNumber = user.Phone,
                Department = user.Department,
                Title = user.Title,
                Groups = user.Groups
            };

            return Ok(response);
        }

    }
}