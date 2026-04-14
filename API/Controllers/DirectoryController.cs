using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Esyasoft.Ldap.Gateway.API.DTOs;
using Esyasoft.Ldap.Gateway.Application.Services;
using Esyasoft.Ldap.Gateway.Domain.Entities;
using Esyasoft.Ldap.Gateway.Domain.Interfaces;
using Esyasoft.Ldap.Gateway.Infrastructure.Configuration;
using System;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;

namespace Esyasoft.Ldap.Gateway.API.Controllers
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

        /// <summary>
        /// Creates a user in three systems atomically:
        ///   1. LDAP    —> authentication account (uid, password, attrs)
        ///   2. Oidc.Server —> AspNetUsers + m_employee + m_login_master
        ///
        /// Password NOT sent to Oidc.Server — AspNetUsers.PasswordHash = null.
        /// LDAP owns authentication.
        /// </summary>
        [HttpPost("new-consumer")]
        [Authorize]
        public async Task<IActionResult> CreateNewConsumer(
            [FromBody] NewConsumerRequest request,
            [FromServices] IHttpClientFactory httpClientFactory,
            [FromServices] IConfiguration configuration)
        {
            // ── Input validation ───────────────────────────────────────
            if (request == null || string.IsNullOrWhiteSpace(request.FullName))
                return BadRequest("FullName is required.");
            if (string.IsNullOrWhiteSpace(request.Department))
                return BadRequest("Department is required.");

            // ── STEP 1: Create in OpenLDAP ─────────────────────────────
            CreateConsumerResult ldapResult;
            try
            {
                var command = new CreateConsumerCommand
                {
                    FullName = request.FullName,
                    Department = request.Department,
                    Title = request.Title ?? string.Empty,
                    TelephoneNumber = request.TelephoneNumber ?? string.Empty,
                    ManagerEmail = request.ManagerEmail,
                    StreetAddress = request.StreetAddress,
                    City = request.City,
                    State = request.State,
                    PostalCode = request.PostalCode,
                    Country = request.Country,
                    Address2 = request.Address2,
                    Address3 = request.Address3,
                    Gender = request.Gender,
                    EmployeeType = request.EmployeeType,
                    Branch = request.Branch,
                    OrgId = request.OrgId,
                    Remark = request.Remark,
                    ModifiedBy = request.ModifiedBy
                };

                ldapResult = await _directoryService.CreateConsumerAsync(command);

                Console.WriteLine($"[NewConsumer] Step 1 OK — LDAP user created: {ldapResult.Username}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[NewConsumer] Step 1 FAILED — LDAP creation for: {request.FullName}");
                return StatusCode(500, new
                {
                    error = "Failed to create user in OpenLDAP.",
                    message = ex.Message,
                    step = "ldap"
                });
            }

            // ── STEP 2: Provision in PostgreSQL via Oidc.Server ────────
            // Sends: username, email, firstName, lastName, and all
            // m_employee / m_login_master fields.
            // Does NOT send password — AspNetUsers.PasswordHash = null.
            string postgresUserId;
            try
            {
                var oidcServerBaseUrl = configuration["OidcServer:BaseUrl"]
                    ?? throw new InvalidOperationException(
                        "'OidcServer:BaseUrl' missing from appsettings.json");

                var httpClient = httpClientFactory.CreateClient("OidcServer");

                // Build the provision request — NO PASSWORD
                var provisionRequest = new
                {
                    Username = ldapResult.Username,
                    Email = ldapResult.Email,
                    FirstName = ldapResult.FirstName,
                    LastName = ldapResult.LastName,

                    // m_employee fields
                    Department = request.Department,
                    Title = request.Title,
                    TelephoneNumber = request.TelephoneNumber,
                    ManagerEmail = request.ManagerEmail,
                    StreetAddress = request.StreetAddress,
                    Address2 = request.Address2,
                    Address3 = request.Address3,
                    City = request.City,
                    State = request.State,
                    PostalCode = request.PostalCode,
                    Country = request.Country,
                    Gender = request.Gender?.ToString(),
                    EmployeeType = request.EmployeeType,
                    Branch = request.Branch,
                    OrgId = request.OrgId,
                    Remark = request.Remark,
                    ModifiedBy = request.ModifiedBy
                };

                var response = await httpClient.PostAsJsonAsync(
                    $"{oidcServerBaseUrl}/api/internal/provision-ldap-user",
                    provisionRequest);

                if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(
                         $"[NewConsumer] Step 2 FAILED — PostgreSQL provisioning " +
                         $"failed for {ldapResult.Username}. HTTP {(int)response.StatusCode}: {errorBody}. " +
                         $"Rolling back LDAP.");
                    await RollbackLdapUser(ldapResult.DistinguishedName);

                    return StatusCode(500, new
                    {
                        error = "Failed to create user in PostgreSQL. " +
                                  "OpenLDAP user has been removed (rollback).",
                        message = errorBody,
                        step = "postgres"
                    });
                }

                var responseBody = await response.Content.ReadAsStringAsync();
                var jsonOptions = new JsonSerializerOptions
                { PropertyNameCaseInsensitive = true };
                var provisionResult = JsonSerializer
                    .Deserialize<ProvisionLdapUserInternalResponse>(
                        responseBody, jsonOptions);

                postgresUserId = provisionResult?.UserId ?? string.Empty;
                Console.WriteLine(
                        $"[NewConsumer] Step 2 OK — PostgreSQL records created for " +
                        $"{ldapResult.Username}, ID: {postgresUserId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                        $"[NewConsumer] Step 2 FAILED — exception for {ldapResult.Username}. " +
                        $"Rolling back LDAP.");

                await RollbackLdapUser(ldapResult.DistinguishedName);

                return StatusCode(500, new
                {
                    error = "An error occurred creating the PostgreSQL records. " +
                              "OpenLDAP user has been removed (rollback).",
                    message = ex.Message,
                    step = "postgres"
                });
            }

            Console.WriteLine($"[NewConsumer] SUCCESS — '{ldapResult.Username}' created in OpenLDAP and PostgreSQL.");

            return Ok(new NewConsumerResponse
            {
                Username = ldapResult.Username,
                InitialPassword = ldapResult.InitialPassword,
                Email = ldapResult.Email,
                DistinguishedName = ldapResult.DistinguishedName,
                PostgresUserId = postgresUserId,
                FirstName = ldapResult.FirstName,
                LastName = ldapResult.LastName
            });
        }

        /// <summary>
        /// Updates a user across all three systems:
        ///   1. LDAP    —> LDAP attributes + OU move if dept changes
        ///   2. Oidc.Server —> AspNetUsers + m_employee + m_login_master
        ///
        /// Rollback strategy:
        ///   If step 2 fails → revert LDAP to its pre-update state.
        ///   If LDAP rollback also fails → both failures logged,
        ///   original update error returned to caller.
        ///
        /// Password is excluded — use separate endpoints for password change.
        /// </summary>
        [HttpPatch("update-consumer")]
        [Authorize]
        public async Task<IActionResult> UpdateConsumer(
            [FromBody] UpdateConsumerRequest request,
            [FromServices] IHttpClientFactory httpClientFactory,
            [FromServices] IConfiguration configuration)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Username))
                return BadRequest("Username is required.");

            // ── STEP 1: Update OpenLDAP ────────────────────────────────
            // Read current LDAP state BEFORE update for rollback snapshot
            // (get current profile so we can revert if step 2 fails)
            DirectoryUser? preUpdateSnapshot = null;
            try
            {
                preUpdateSnapshot = await _directoryService
                    .GetMyProfileAsync(request.Username);
            }
            catch
            {
                // Snapshot failure is non-fatal — rollback will be best-effort
                Console.WriteLine($"[UpdateConsumer] Could not snapshot pre-update state for {request.Username}");
            }

            try
            {
                var command = new UpdateConsumerCommand
                {
                    Username = request.Username,
                    DisplayName = request.DisplayName,
                    Email = request.Email,
                    Title = request.Title,
                    TelephoneNumber = request.TelephoneNumber,
                    Department = request.Department,
                    ManagerEmail = request.ManagerEmail,
                    StreetAddress = request.StreetAddress,
                    City = request.City,
                    State = request.State,
                    PostalCode = request.PostalCode,
                    Country = request.Country,
                    Address2 = request.Address2,
                    Address3 = request.Address3,
                    Gender = request.Gender,
                    EmployeeType = request.EmployeeType,
                    Branch = request.Branch,
                    OrgId = request.OrgId,
                    Remark = request.Remark,
                    ModifiedBy = request.ModifiedBy
                };

                await _directoryService.UpdateConsumerAsync(command);

                Console.WriteLine($"[UpdateConsumer] Step 1 OK — LDAP updated for {request.Username}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[UpdateConsumer] Step 1 FAILED — LDAP update for {request.Username}");
                return StatusCode(500, new
                {
                    error = "Failed to update user in OpenLDAP.",
                    message = ex.Message,
                    step = "ldap"
                });
            }

            // ── STEP 2: Update PostgreSQL via Oidc.Server ──────────────
            try
            {
                var oidcServerBaseUrl = configuration["OidcServer:BaseUrl"]
                    ?? throw new InvalidOperationException(
                        "'OidcServer:BaseUrl' missing from appsettings.json");

                var httpClient = httpClientFactory.CreateClient("OidcServer");

                // Build update request — matches Oidc.Server internal DTO
                var updateRequest = new
                {
                    Username = request.Username,
                    Email = request.Email,
                    FirstName = request.DisplayName?.Split(' ')
                                        .FirstOrDefault(),
                    LastName = request.DisplayName?.Contains(' ') == true
                                        ? string.Join(" ",
                                            request.DisplayName.Split(' ').Skip(1))
                                        : null,
                    Department = request.Department,
                    Title = request.Title,
                    TelephoneNumber = request.TelephoneNumber,
                    ManagerEmail = request.ManagerEmail,
                    StreetAddress = request.StreetAddress,
                    Address2 = request.Address2,
                    Address3 = request.Address3,
                    City = request.City,
                    State = request.State,
                    PostalCode = request.PostalCode,
                    Country = request.Country,
                    Gender = request.Gender?.ToString(),
                    EmployeeType = request.EmployeeType,
                    Branch = request.Branch,
                    OrgId = request.OrgId,
                    Remark = request.Remark,
                    ModifiedBy = request.ModifiedBy
                };

                var response = await httpClient.PatchAsJsonAsync(
                    $"{oidcServerBaseUrl}/api/internal/update-consumer",
                    updateRequest);

                if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(
                          $"[UpdateConsumer] Step 2 FAILED — PostgreSQL update " +
                          $"failed for {request.Username}. HTTP {(int)response.StatusCode}: {errorBody}. " +
                          $"Attempting LDAP rollback.");

                    // ── Rollback step 1 (LDAP) ─────────────────────────
                    await RollbackLdapUpdate(
                        request.Username, preUpdateSnapshot);

                    return StatusCode(500, new
                    {
                        error = "Failed to update PostgreSQL records. " +
                                  "OpenLDAP has been reverted.",
                        message = errorBody,
                        step = "postgres"
                    });
                }

                Console.WriteLine($"[UpdateConsumer] Step 2 OK — PostgreSQL updated for {request.Username}");
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                        $"[UpdateConsumer] Step 2 FAILED — exception for {request.Username}. " +
                        $"Attempting LDAP rollback.");

                await RollbackLdapUpdate(
                    request.Username, preUpdateSnapshot);

                return StatusCode(500, new
                {
                    error = "An error occurred updating PostgreSQL. " +
                              "OpenLDAP has been reverted.",
                    message = ex.Message,
                    step = "postgres"
                });
            }

            Console.WriteLine($"[UpdateConsumer] SUCCESS — '{request.Username}' updated in all systems.");

            return NoContent();
        }

        /// <summary>
        /// Reverts LDAP to the pre-update snapshot when PostgreSQL update fails.
        /// Uses existing UpdateMyProfileAsync to apply the old values back.
        /// Best-effort — logs failure but does not throw.
        /// </summary>
        private async Task RollbackLdapUpdate(
            string username,
            DirectoryUser? snapshot)
        {
            if (snapshot == null)
            {
                Console.WriteLine(
                     $"[UpdateConsumer] No snapshot available for {username}. " +
                     $"LDAP rollback skipped — manual correction may be needed.");
                return;
            }

            try
            {
                var revertProfile = new UpdateMyProfile
                {
                    DisplayName = snapshot.DisplayName,
                    TelephoneNumber = snapshot.Phone,
                    // Note: description-based fields (city, state etc.) are
                    // preserved because UpdateMyProfileAsync only updates
                    // fields that are non-null — fields not provided here
                    // will keep their LDAP values from before our update.
                };

                await _directoryService.UpdateMyProfileAsync(username, revertProfile);

                Console.WriteLine($"[UpdateConsumer] LDAP rollback succeeded for {username}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[UpdateConsumer] LDAP ROLLBACK FAILED for {username}. " +
                    $"Manual correction required — LDAP and PostgreSQL may be out of sync.");
            }
        }

        /// <summary>
        /// Deletes a user from OpenLDAP when PostgreSQL provisioning fails.
        /// Layman: If step 2 fails, undo step 1 so we don't have an orphaned LDAP user.
        /// </summary>
        private async Task RollbackLdapUser(string distinguishedName)
        {
            try
            {
                // Full chain: DirectoryService → IUserRepository → LdapUserRepository
                await _directoryService.DeleteUserAsync(distinguishedName);

                Console.WriteLine($"[NewConsumer] Rollback succeeded — LDAP user removed: {distinguishedName}");
            }
            catch (Exception ex)
            {
                // Rollback itself failed — log clearly for manual cleanup
                // Do NOT throw — we still need to return the original error to the caller
                Console.WriteLine(
                     $"[NewConsumer] ROLLBACK FAILED — manual cleanup required. " +
                     $"Please delete this LDAP user manually: {distinguishedName}");
            }
        }

        // ── Private DTO for Oidc.Server response ──────────────────────────────
        private class ProvisionLdapUserInternalResponse
        {
            public string UserId { get; set; } = string.Empty;
            public string Username { get; set; } = string.Empty;
        }


        /// <summary>
        /// DELETE /api/Directory/users/consumer
        ///
        /// Deletes a consumer user from all three systems:
        ///   1. PostgreSQL — m_login_master + m_employee + AspNetUsers
        ///      (via Oidc.Server /api/internal/delete-consumer)
        ///   2. OpenLDAP   — removes the uid entry from the directory
        ///
        /// Returns 204 No Content on success.
        /// Returns 404 if user not found in any system.
        /// Returns 500 with step info if a specific system fails.
        /// </summary>
        [HttpDelete("consumer")]
        [Authorize]
        public async Task<IActionResult> DeleteConsumer(
            [FromBody] DeleteConsumerRequest request,
            [FromServices] IHttpClientFactory httpClientFactory,
            [FromServices] IConfiguration configuration,
            [FromServices] ILogger<DirectoryController> logger)
        {
            // ── Input validation ───────────────────────────────────────
            if (request == null || string.IsNullOrWhiteSpace(request.Username))
                return BadRequest("Username is required.");
 
            logger.LogInformation(
                "[DeleteConsumer] Request to delete '{Username}' by '{DeletedBy}'",
                request.Username, request.DeletedBy ?? "unknown");
 
            // ── STEP 1: Delete from PostgreSQL via Oidc.Server ─────────
            // Done first so that even if LDAP deletion fails,
            // the user cannot obtain claims and is effectively disabled.
            try
            {
                var oidcServerBaseUrl = configuration["OidcServer:BaseUrl"]
                    ?? throw new InvalidOperationException(
                        "'OidcServer:BaseUrl' missing from appsettings.json");
 
                var httpClient = httpClientFactory.CreateClient("OidcServer");
 
                var deleteRequest = new
                {
                    Username  = request.Username,
                    DeletedBy = request.DeletedBy
                };
 
                var requestMessage = new HttpRequestMessage(HttpMethod.Delete, $"{oidcServerBaseUrl}/api/internal/delete-consumer")
                {
                    Content = JsonContent.Create(deleteRequest)
                };
                var response = await httpClient.SendAsync(requestMessage);
 
                if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    logger.LogWarning(
                        "[DeleteConsumer] User '{Username}' not found in " +
                        "PostgreSQL. Proceeding to check LDAP.",
                        request.Username);
                    // Non-fatal — user may only exist in LDAP
                    // Continue to LDAP deletion
                }
                else if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync();
                    logger.LogError(
                        "[DeleteConsumer] Step 1 FAILED — PostgreSQL deletion " +
                        "failed for '{Username}'. HTTP {Status}: {Body}",
                        request.Username, (int)response.StatusCode, errorBody);
 
                    return StatusCode(500, new
                    {
                        error   = "Failed to delete user from PostgreSQL.",
                        message = errorBody,
                        step    = "postgres"
                    });
                }
                else
                {
                    logger.LogInformation(
                        "[DeleteConsumer] Step 1 OK — PostgreSQL records " +
                        "deleted for '{Username}'.", request.Username);
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex,
                    "[DeleteConsumer] Step 1 FAILED — exception during " +
                    "PostgreSQL deletion for '{Username}'.", request.Username);
 
                return StatusCode(500, new
                {
                    error   = "An error occurred deleting PostgreSQL records.",
                    message = ex.Message,
                    step    = "postgres"
                });
            }
 
            // ── STEP 2: Delete from OpenLDAP ───────────────────────────
            try
            {
                var command = new DeleteConsumerCommand
                {
                    Username  = request.Username,
                    DeletedBy = request.DeletedBy
                };
 
                await _directoryService.DeleteConsumerAsync(command);
 
                logger.LogInformation(
                    "[DeleteConsumer] Step 2 OK — LDAP entry deleted for " +
                    "'{Username}'.", request.Username);
            }
            catch (InvalidOperationException ex)
                when (ex.Message.Contains("not found in LDAP"))
            {
                // User did not exist in LDAP — not an error if PG deletion
                // already succeeded. Log a warning and return success.
                logger.LogWarning(
                    "[DeleteConsumer] User '{Username}' was not found in LDAP " +
                    "(already deleted or never created there). " +
                    "PostgreSQL records have been removed.",
                    request.Username);
 
                return NoContent();
            }
            catch (Exception ex)
            {
                // PostgreSQL is already deleted at this point.
                // LDAP entry remains — log clearly for manual cleanup.
                logger.LogError(ex,
                    "[DeleteConsumer] Step 2 FAILED — LDAP deletion failed " +
                    "for '{Username}'. PostgreSQL records are already deleted. " +
                    "MANUAL LDAP CLEANUP REQUIRED.",
                    request.Username);
 
                return StatusCode(500, new
                {
                    error = "PostgreSQL records deleted successfully but " +
                            "LDAP deletion failed. Manual LDAP cleanup required.",
                    message = ex.Message,
                    step = "ldap",
                    manualCleanup = $"Run: ldapdelete -H ldap://<host>:389 " +
                                    $"-D \"cn=admin,dc=corp,dc=local\" " +
                                    $"-w <password> -x " +
                                    $"\"uid={request.Username},ou=<dept>,ou=Employees,dc=corp,dc=local\""
                });
            }
 
            logger.LogInformation(
                "[DeleteConsumer] SUCCESS — '{Username}' deleted from " +
                "OpenLDAP and PostgreSQL.", request.Username);
 
            // 204 No Content — standard REST response for successful DELETE
            return NoContent();
        }
    }
}
