using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SSO_IdentityProvider.API.DTOs;
using SSO_IdentityProvider.Application.Services;
using SSO_IdentityProvider.Domain.Entities;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System;
using System.DirectoryServices.Protocols;
using System.Security.Claims;
using System.Linq;

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


        //[HttpPost("search")]
        //[Authorize]
        //public async Task<IActionResult> SearchUsers([FromBody] SearchUsersRequest request)
        //{
        //    var criteria = new UserSearchCriteria
        //    {
        //        BaseDn = _ldapSettings.BaseDn,
        //        Filters = request.Filters,
        //        Attributes = request.IncludeAttributes?.Any() == true
        //         ? request.IncludeAttributes
        //         : new List<string> { "cn", "uid", "mobile", "mail", "distinguishedName", "memberOf", "description" },
        //        Scope = SearchScope.Subtree,
        //        MaxResults = Math.Clamp(request.MaxResults, 1, 100)
        //    };

        //    var results = await _directoryService.SearchUsersAsync(criteria);
        //    return Ok(results);
        //}

        [HttpPost("search")]
        [Authorize]
        public async Task<IActionResult> SearchUsers([FromBody] SearchUsersRequest request)
        {
            try
            {
                // Convert user-friendly search filters to dictionary format
                var filters = ConvertSearchFiltersToDictionary(request.SearchFilters, request.Filters);

                // Convert user-friendly attribute selector to list format
                var attributes = ConvertAttributesToList(request.Attributes, request.IncludeAttributes);

                // Prepare search criteria
                var criteria = new UserSearchCriteria
                {
                    BaseDn = _ldapSettings.BaseDn, 
                    Filters = filters ?? new Dictionary<string, string>(),
                    Attributes = attributes ?? new List<string>
                    {
                        "Username",
                        "DisplayName",
                        "Email"
                    },
                    Scope = SearchScope.Subtree,
                    MaxResults = Math.Clamp(request.MaxResults, 1, 1000)
                };

                var results = await _directoryService.SearchUsersAsync(criteria);
                Console.WriteLine($"Search completed. Found {results.Count} results.");

                return Ok(new
                {
                    Count = results.Count,
                    Results = results
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Search error: {ex.Message}");
                return StatusCode(500, new { Error = "Search failed", Message = ex.Message });
            }
        }

        private Dictionary<string, string>? ConvertSearchFiltersToDictionary(UserSearchFilters? searchFilters, Dictionary<string, string>? existingFilters)
        {
            // If no search filters provided, return existing filters (could be null)
            if (searchFilters == null)
                return existingFilters;

            var result = new Dictionary<string, string>();

            // Copy existing filters if any (for backward compatibility)
            if (existingFilters != null)
            {
                foreach (var kvp in existingFilters)
                {
                    result[kvp.Key] = kvp.Value;
                }
            }

            // Map user-friendly filters to the attribute names expected by the mapper
            AddFilterIfNotNull(result, "Username", searchFilters.Username);
            AddFilterIfNotNull(result, "DisplayName", searchFilters.DisplayName);
            AddFilterIfNotNull(result, "Email", searchFilters.Email);
            if (!string.IsNullOrWhiteSpace(searchFilters.Department))
            {
                result["Department"] = searchFilters.Department;
            }
            AddFilterIfNotNull(result, "Title", searchFilters.Title);
            AddFilterIfNotNull(result, "ManagerEmail", searchFilters.ManagerEmail);
            AddFilterIfNotNull(result, "AccountStatus", searchFilters.AccountStatus);
            AddFilterIfNotNull(result, "Phone", searchFilters.Phone);
            AddFilterIfNotNull(result, "City", searchFilters.City);
            AddFilterIfNotNull(result, "State", searchFilters.State);
            AddFilterIfNotNull(result, "PostalCode", searchFilters.PostalCode);
            AddFilterIfNotNull(result, "Country", searchFilters.Country);

            return result;
        }
        private List<string>? ConvertAttributesToList(UserAttributesRequest? attributes, List<string>? existingAttributes)
        {
            // If no attributes selector provided, return existing attributes (could be null)
            if (attributes == null)
                return existingAttributes;

            var result = new List<string>();

            // If IncludeAll is true, add all available attributes
            if (attributes.IncludeAll)
            {
                result.AddRange(new[]
                {
                    "Username", "DistinguishedName", "DisplayName", "Email",
                    "Department", "Title", "Phone", "Manager", "AccountStatus",
                    "Groups", "StreetAddress", "City", "State",
                    "PostalCode", "Country"
                });
                return result;
            }

            // Add individual attributes based on boolean flags
            if (attributes.IncludeUsername) result.Add("Username");
            if (attributes.IncludeDistinguishedName) result.Add("DistinguishedName");
            if (attributes.IncludeDisplayName) result.Add("DisplayName");
            if (attributes.IncludeEmail) result.Add("Email");
            if (attributes.IncludeDepartment) result.Add("Department");
            if (attributes.IncludeTitle) result.Add("Title");
            if (attributes.IncludePhone) result.Add("Phone");
            if (attributes.IncludeManager) result.Add("Manager");
            if (attributes.IncludeAccountStatus) result.Add("AccountStatus");
            if (attributes.IncludeGroups) result.Add("Groups");

            // Handle address attributes as a group
            if (attributes.IncludeAddress)
            {
                result.AddRange(new[] { "StreetAddress", "City", "State", "PostalCode", "Country" });
            }

            // If no attributes selected, return defaults
            if (result.Count == 0)
            {
                result.AddRange(new[] { "Username", "DisplayName", "Email" });
            }

            return result;
        }
        private void AddFilterIfNotNull(Dictionary<string, string> filters, string key, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                filters[key] = value;
            }
        }


        [HttpPatch("update-my-profile")]
        [Authorize]
        public async Task<IActionResult> UpdateMyProfile([FromBody] UpdateMyProfileRequest request)
        {
            var username = User.Identity?.Name; // extracts unique ID from the access token sent in the Header
            if (string.IsNullOrWhiteSpace(username)) return Unauthorized();

            var domainModel = new UpdateMyProfile
            {
                DisplayName = request.DisplayName,
                TelephoneNumber = request.TelephoneNumber,
                StreetAddress = request.StreetAddress,
                City = request.City,
                State = request.State,
                PostalCode = request.PostalCode,
                Country = request.Country,
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
            if (string.IsNullOrWhiteSpace(request.ParentOuDn))
            {
                return BadRequest("Parent OU DN is required");
            }

            if (string.IsNullOrWhiteSpace(request.NewOuName))
            {
                return BadRequest("New OU name is required");
            }

            // Validate OU name doesn't contain special characters
            if (request.NewOuName.Any(c => "\\,+\"<>;=".Contains(c)))
            {
                return BadRequest("OU name contains invalid characters");
            }

            await _directoryService.CreateOuAsync(new CreateOuCommand
            {
                ParentOuDn = request.ParentOuDn,
                NewOuName = request.NewOuName
            });

            return NoContent();
        }

        [HttpDelete("remove-ou")]
        [Authorize]
        public async Task<IActionResult> DeleteOu([FromQuery] string ouDn, [FromQuery] bool cascadeDelete = false)
        {
            if (string.IsNullOrWhiteSpace(ouDn))
            {
                return BadRequest("OU DN is required");
            }

            // Prevent deletion of critical OUs
            var criticalOus = new[]
            {
                "ou=Employees,dc=corp,dc=local",
                "dc=corp,dc=local"
            };

            var normalizedOuDn = ouDn.Trim().ToLower();
            foreach (var criticalOu in criticalOus)
            {
                if (normalizedOuDn == criticalOu.ToLower())
                {
                    return BadRequest(new
                    {
                        error = "Cannot delete critical organizational unit",
                        criticalOu = criticalOu
                    });
                }
            }

            try
            {
                await _directoryService.DeleteOuAsync(new DeleteOuCommand
                {
                    OuDn = ouDn,
                    CascadeDelete = cascadeDelete
                });

                return NoContent();
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { error = $"Internal server error: {ex.Message}" });
            }
        }

    }
}
