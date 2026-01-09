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
                Filters = request.Filters?.Any() == true ? request.Filters : new Dictionary<string, string> { { "objectClass", "user" } },
                Attributes = request.IncludeAttributes?.Any() == true
                 ? request.IncludeAttributes
                 : new List<string> { "cn", "sAMAccountName", "mobile", "mail", "distinguishedName", "memberOf" },
                Scope = SearchScope.Subtree,
                MaxResults = Math.Clamp(request.MaxResults, 1, 100)
            };

            var results = await _directoryService.SearchUsersAsync(criteria);
            return Ok(results);
        }

        [HttpPatch("update-my-profile")]
        [Authorize]
        public async Task<IActionResult> UpdateMyProfile([FromBody] UpdateMyProfileRequest request)
        {
            var username = User.Identity?.Name; // from the token sent in the Header
            if (string.IsNullOrWhiteSpace(username)) return Unauthorized();

            var domainModel = new UpdateMyProfile
            {
                DisplayName = request.DisplayName,
                TelephoneNumber = request.TelephoneNumber,
                StreetAddress = request.StreetAddress,
                City = request.City,
                State = request.State,
                PostalCode = request.PostalCode,
                NewPassword = request.NewPassword
            };

            await _directoryService.UpdateMyProfileAsync(username, domainModel);

            return NoContent();
        }


        [HttpPost("add-new-user")]
        [Authorize]
        public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
        {
            var domainModel = new CreateUserCommand
            {
                FullName = request.FullName,
                Department = request.Department,
                Title = request.Title,
                ManagerEmail = request.ManagerEmail,
                TelephoneNumber = request.TelephoneNumber,
                City = request.City,
                State = request.State,
                Country = request.Country,
                PostalCode = request.PostalCode,
                StreetAddress = request.StreetAddress
            };
            var userDn = await _directoryService.CreateUserAsync(domainModel);
            return Ok(userDn);
        }

        [HttpPatch("admin-update")]
        [Authorize] 
        public async Task<IActionResult> AdminUpdateUser([FromBody] AdminUpdateUserRequest request)
        {
            var command = new AdminUpdateUserCommand
            {
                Email = request.Email,
                Department = request.Department,
                Title = request.Title,
                ManagerEmail = request.ManagerEmail
            };

            await _directoryService.UpdateUserAsAdminAsync(command);
            return NoContent();
        }

        [HttpPatch("update-status")]
        [Authorize]
        public async Task<IActionResult> UpdateUserStatus([FromBody] UpdateUserStatusRequest request)
        {
            var command = new UpdateUserStatusCommand
            {
                Email = request.Email,
                IsEnabled = request.IsEnabled
            };

            await _directoryService.UpdateUserStatusAsync(command);

            return NoContent();
        }


        [HttpPost("add-ou")]
        [Authorize]
        public async Task<IActionResult> CreateOu([FromBody] CreateOuCommand request)
        {
            await _directoryService.CreateOuAsync(new CreateOuCommand
            {
                ParentOuDn = request.ParentOuDn,
                NewOuName = request.NewOuName
            });

            return NoContent();
        }

        [HttpDelete("remove-ou")]
        [Authorize]
        public async Task<IActionResult> DeleteOu([FromBody] DeleteOuCommand request)
        {
            await _directoryService.DeleteOuAsync(new DeleteOuCommand
            {
                OuDn = request.OuDn,
                CascadeDelete = request.CascadeDelete
            });

            return NoContent();
        }

    }
}
