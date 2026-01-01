using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SSO_IdentityProvider.API.DTOs;
using SSO_IdentityProvider.Application.Services;
using SSO_IdentityProvider.Domain.Entities;
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

        public DirectoryController(DirectoryService directoryService)
        {
            _directoryService = directoryService;
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
            if (request.IncludeAttributes == null || !request.IncludeAttributes.Any())
                return BadRequest("Attributes are required.");

            if (!Enum.TryParse<SearchScope>(request.Scope,ignoreCase: true,out var scope))
            {
                return BadRequest("Invalid scope. Use Base | OneLevel | Subtree.");
            }

            var criteria = new UserSearchCriteria
            {
                BaseDn = request.BaseDn,
                Filters = request.Filters ?? new(),
                Attributes = request.IncludeAttributes,
                Scope = scope,
                MaxResults = request.MaxResults <= 0 ? 50 : request.MaxResults
            };

            var results = await _directoryService.SearchUsersAsync(criteria);
            return Ok(results);
        }
    }
}
