using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SSO_IdentityProvider.API.DTOs;
using SSO_IdentityProvider.Application.Services;
using SSO_IdentityProvider.Domain.Entities;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System.DirectoryServices.Protocols;
using System.Security.Claims;

namespace SSO_IdentityProvider.API.Controllers
{
    [ApiController]
    [Route("api/[controller]/users")]
    [Authorize]
    public class DirectoryController : ControllerBase
    {
        private readonly DirectoryService _directoryService;
        private readonly LdapSettings _ldapSettings;
        public DirectoryController(DirectoryService directoryService, IOptions<LdapSettings> Options)
        {
            _directoryService = directoryService;
            _ldapSettings = Options.Value;

            Console.WriteLine($"LDAP Settings in Controller: {_ldapSettings.Host} : {_ldapSettings.Port} : {_ldapSettings.username} : {_ldapSettings.Domain}");
        }

        
        [HttpGet("me")]
        public async Task<IActionResult> GetMyProfile()
        {
            var username = User.Identity?.Name;

            if (string.IsNullOrWhiteSpace(username)) return Unauthorized();

            var user = await _directoryService.GetMyProfileAsync(username);

            return Ok(user);
        }


        [HttpPost("search")]
        [Authorize]
        public async Task<IActionResult> SearchUsers([FromBody] SearchUsersRequest request)
        {
            var criteria = new UserSearchCriteria
            {
                BaseDn = _ldapSettings.BaseDn,
                Filters = request.Filters?.Any() == true ? request.Filters : new Dictionary<string, string> {{ "objectClass", "user" }},
                Attributes = request.IncludeAttributes?.Any() == true
                 ? request.IncludeAttributes
                 : new List<string> { "cn", "sAMAccountName", "mobile", "mail", "distinguishedName", "memberOf" },
                Scope = SearchScope.Subtree,
                MaxResults = Math.Clamp(request.MaxResults, 1, 100)
            };

            var results = await _directoryService.SearchUsersAsync(criteria);
            return Ok(results);
        }

        [HttpPatch("me")]
        [Authorize]
        public async Task<IActionResult> UpdateMyProfile([FromBody] UpdateMyProfileRequest request)
        {
            var username = User.Identity?.Name; // from the token sent in the Header
            if (string.IsNullOrWhiteSpace(username)) return Unauthorized();

            var domainModel = new UpdateMyProfile
            {
                DisplayName = request.DisplayName,
                TelephoneNumber = request.TelephoneNumber,
                Mobile = request.Mobile,
                StreetAddress = request.StreetAddress,
                City = request.City,
                State = request.State,
                PostalCode = request.PostalCode,
                NewPassword = request.NewPassword
            };

            await _directoryService.UpdateMyProfileAsync(username, domainModel);

            return NoContent();
        }

    }
}
