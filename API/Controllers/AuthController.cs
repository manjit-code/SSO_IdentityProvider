using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SSO_IdentityProvider.API.DTOs;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System.DirectoryServices.Protocols;
using System.Net;

namespace SSO_IdentityProvider.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IAuthenticationService _authenticationService;
        private readonly LdapSettings _ldapSettings;
        public AuthController(IAuthenticationService authenticationService, IOptions<LdapSettings> options)
        {
            _authenticationService = authenticationService;
            _ldapSettings = options.Value;
        }

        
        [HttpGet("ldap-health")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public IActionResult LdapHealth()
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(
                    _ldapSettings.Host,
                    _ldapSettings.Port,
                    _ldapSettings.UseSsl,
                    false
                );

                var credential = new NetworkCredential(_ldapSettings.username, _ldapSettings.password);
                using var connection = new LdapConnection(identifier)
                {
                    AuthType = AuthType.Basic,
                    Credential = credential
                };

                connection.SessionOptions.ProtocolVersion = 3;
                if (_ldapSettings.UseSsl)
                {
                    connection.SessionOptions.SecureSocketLayer = true;
                    connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;
                }
                connection.Bind();

                return Ok(new
                {
                    Status = "LDAP reachable and credentials valid",
                    Host = _ldapSettings.Host,
                    Port = _ldapSettings.Port,
                    UseSsl = _ldapSettings.UseSsl
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }



        [HttpPost("login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Username and password must be provided.");
            }

            try
            {
                var token = await _authenticationService.AuthenticateAsync(request.Username, request.Password);
                if (token == null) {
                    return Unauthorized("Invalid username or password.");
                }
                return Ok(new TokenResponse { AccessToken = token });
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized("Invalid username or password.");
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"An error occurred: {ex.Message}");
            }
        }


        [Authorize]
        [HttpGet("secure")]
        public IActionResult Secure()
        {
            return Ok(new
            {
                User = User.Identity?.Name,
                Claims = User.Claims.Select(c => new { c.Type, c.Value })
            });
        }

    }
}
