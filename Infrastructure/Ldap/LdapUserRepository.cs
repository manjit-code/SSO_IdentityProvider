using Microsoft.Extensions.Options;
using SSO_IdentityProvider.Domain.Entities;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Infrastructure.Configuration;
using SSO_IdentityProvider.Infrastructure.Mapper;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace SSO_IdentityProvider.Infrastructure.Ldap
{
    public class LdapUserRepository : IUserRepository
    {
        private readonly LdapSettings _ldapSettings;
        private readonly ILdapAuthenticator _ldapAuthenticator;
        private readonly AttributeMapper _attributeMapper;
        public LdapUserRepository(IOptions<LdapSettings> option, ILdapAuthenticator ldapAuthenticator, AttributeMapper attributeMapper)
        {
            _ldapSettings = option.Value;
            _ldapAuthenticator = ldapAuthenticator;
            _attributeMapper = attributeMapper;
        }

        public async Task<User?> GetByUsernameAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() =>
            {
                string usernameAttribute = _attributeMapper.GetUsernameSearchAttribute();
                string emailAttribute = _attributeMapper.GetEmailSearchAttribute();

                var searchFilter = username.Contains("@")
                            ? $"({emailAttribute}={Escape(username)})"
                            : $"({usernameAttribute}={Escape(username)})";

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    searchFilter,
                    SearchScope.Subtree,
                    usernameAttribute, emailAttribute, "dn"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                if (entry == null)
                {
                    return null;
                }

                //string userName = entry.Attributes[usernameAttribute]?[0]?.ToString() ?? username;

                string extractedUsername;
                if (_attributeMapper.IsActiveDirectory)
                {
                    extractedUsername = entry.Attributes["sAMAccountName"]?[0]?.ToString()
                        ?? entry.Attributes["userPrincipalName"]?[0]?.ToString()?.Split('@')[0]
                        ?? username;
                }
                else
                {
                    extractedUsername = entry.Attributes[usernameAttribute]?[0]?.ToString()
                        ?? entry.Attributes[emailAttribute]?[0]?.ToString()?.Split('@')[0]
                        ?? username;
                }

                var newUser = new User
                {
                    UserName = extractedUsername,
                    DistinguishedName = entry.DistinguishedName
                };

                return newUser;
            });
        }

        public async Task<DirectoryUser?> GetMyProfileAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() =>
            {
                string usernameAttribute = _attributeMapper.MapAttribute("Username");
                string emailAttribute = _attributeMapper.MapAttribute("Email");

                var searchFilter = username.Contains("@")
                        ? $"({emailAttribute}={Escape(username)})"
                        : $"({usernameAttribute}={Escape(username)})";

                var requestAttributes = new List<string>
                {
                    "distinguishedName",
                    _attributeMapper.MapAttribute("DisplayName"),
                    _attributeMapper.MapAttribute("Email"),
                    _attributeMapper.MapAttribute("Phone"),
                    _attributeMapper.MapAttribute("Title"),
                    _attributeMapper.MapAttribute("Manager"),
                    _attributeMapper.MapAttribute("MemberOf")
                };
                // Add department attribute (handled differently for OpenLDAP vs AD)
                if (_attributeMapper.IsActiveDirectory)
                {
                    requestAttributes.Add(_attributeMapper.MapAttribute("Department"));
                    if (_attributeMapper.UseAdAccountControl)
                    {
                        requestAttributes.Add(_attributeMapper.MapAttribute("AccountStatus"));
                    }
                }
                else
                {
                    // For OpenLDAP, department is in description
                    requestAttributes.Add("description");
                }

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    searchFilter,
                    SearchScope.Subtree,
                    requestAttributes.ToArray()
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();

                if (entry == null) return null;

                var groups = new List<string>();
                string memberOfAttribute = _attributeMapper.MapAttribute("MemberOf");
                if (entry.Attributes.Contains(memberOfAttribute))
                {
                    var groupDns = entry.Attributes[memberOfAttribute]
                        .GetValues(typeof(string))
                        .Cast<string>();

                    groups = groupDns
                        .Select(dn => _attributeMapper.ExtractGroupNameFromDn(dn))
                        .Where(name => !string.IsNullOrEmpty(name))
                        .ToList();
                }

                // Extract department based on LDAP type
                string? department = null;
                if (_attributeMapper.IsActiveDirectory)
                {
                    // AD: department is a separate attribute
                    string deptAttribute = _attributeMapper.MapAttribute("Department");
                    if (entry.Attributes.Contains(deptAttribute))
                    {
                        department = entry.Attributes[deptAttribute][0]?.ToString();
                    }
                }
                else
                {
                    // OpenLDAP: department is in description
                    var description = entry.Attributes["description"]?[0]?.ToString();
                    var descriptionAttributes = ParseDescriptionAttributes(description);
                    if (descriptionAttributes.TryGetValue("Department", out var deptValue))
                    {
                        department = deptValue;
                    }
                }

                // Check account status: Multiple Possible Keys Checks
                bool isEnabled = true;
                if (_attributeMapper.IsActiveDirectory && _attributeMapper.UseAdAccountControl)
                {
                    // AD: Use userAccountControl attribute
                    string statusAttribute = _attributeMapper.MapAttribute("AccountStatus");
                    if (entry.Attributes.Contains(statusAttribute))
                    {
                        var statusValue = entry.Attributes[statusAttribute][0]?.ToString();
                        if (int.TryParse(statusValue, out int userAccountControl))
                        {
                            isEnabled = (userAccountControl & 2) == 0; // Account disabled flag
                        }
                    }
                }
                else
                {
                    // OpenLDAP: Parse from description
                    var description = entry.Attributes["description"]?[0]?.ToString();
                    var descriptionAttributes = ParseDescriptionAttributes(description);

                    if (descriptionAttributes.TryGetValue("Account Status", out var statusValue))
                    {
                        isEnabled = !statusValue.Contains("Disabled", StringComparison.OrdinalIgnoreCase);
                    }
                    else if (descriptionAttributes.TryGetValue("Status", out var altStatusValue))
                    {
                        isEnabled = !altStatusValue.Contains("Disabled", StringComparison.OrdinalIgnoreCase);
                    }
                }

                // Extract username 
                string extractedUsername;
                if (_attributeMapper.IsActiveDirectory)
                {
                    extractedUsername = entry.Attributes["sAMAccountName"]?[0]?.ToString()
                        ?? entry.Attributes["userPrincipalName"]?[0]?.ToString()?.Split('@')[0]
                        ?? username;
                }
                else
                {
                    extractedUsername = entry.Attributes["uid"]?[0]?.ToString()
                        ?? entry.Attributes["mail"]?[0]?.ToString()?.Split('@')[0]
                        ?? username;
                }

                return new DirectoryUser
                {
                    Username = extractedUsername,
                    DistinguishedName = entry.DistinguishedName,
                    DisplayName = entry.Attributes[_attributeMapper.MapAttribute("DisplayName")]?[0]?.ToString(),
                    Email = entry.Attributes[_attributeMapper.MapAttribute("Email")]?[0]?.ToString(),
                    Phone = entry.Attributes[_attributeMapper.MapAttribute("Phone")]?[0]?.ToString(),
                    Department =department,
                    Title = entry.Attributes[_attributeMapper.MapAttribute("Title")]?[0]?.ToString(),
                    Manager = entry.Attributes[_attributeMapper.MapAttribute("Manager")]?[0]?.ToString(),
                    Groups = groups,
                    IsEnabled = isEnabled
                };
            });
        }

        private Dictionary<string, string> ParseDescriptionAttributes(string? description)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(description)) return result;

            // Split by semicolon and process each part
            var parts = description.Split(';', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmedPart = part.Trim();
                var colonIndex = trimmedPart.IndexOf(':');

                if (colonIndex > 0)
                {
                    var key = trimmedPart.Substring(0, colonIndex).Trim();
                    var value = trimmedPart.Substring(colonIndex + 1).Trim();

                    if (!string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(value))
                    {
                        result[key] = value;
                    }
                }
            }

            return result;
        }

        public async Task<IReadOnlyCollection<DirectorySearchResult>> SearchUsersAsync(LdapConnection connection, UserSearchCriteria reqBody)
        {
            return await Task.Run(() =>
            {
                // Use configured base DN or provided one
                var searchBaseDn = string.IsNullOrWhiteSpace(reqBody.BaseDn)
                    ? _ldapSettings.BaseDn
                    : reqBody.BaseDn;

                var filterParts = new List<string>();

                // Start with base object class filter
                filterParts.Add(_attributeMapper.GetUserSearchFilter());

                // Process filters if provided
                if (reqBody.Filters != null && reqBody.Filters.Any())
                {
                    // Handle OU filter specially (changes search base)
                    if (reqBody.Filters.TryGetValue("ou", out var ouValue) && !string.IsNullOrWhiteSpace(ouValue))
                    {
                        if (!ouValue.Contains("dc="))
                        {
                            // Simple OU name, try different formats
                            var possibleOus = new[]
                            {
                        $"ou={Escape(ouValue)},{_ldapSettings.BaseDn}",
                        $"ou={Escape(ouValue)},ou=Employees,{_ldapSettings.BaseDn}",
                        $"ou={Escape(ouValue)},ou=Departments,{_ldapSettings.BaseDn}"
                    };

                            // Find which OU actually exists
                            foreach (var possibleOu in possibleOus)
                            {
                                try
                                {
                                    var checkRequest = new SearchRequest(
                                        possibleOu,
                                        "(objectClass=*)",
                                        SearchScope.Base,
                                        "ou"
                                    );
                                    var checkResponse = (SearchResponse)connection.SendRequest(checkRequest);
                                    if (checkResponse.Entries.Count > 0)
                                    {
                                        searchBaseDn = possibleOu;
                                        Console.WriteLine($"Found OU at: {searchBaseDn}");
                                        break;
                                    }
                                }
                                catch
                                {
                                    // Try next possible location
                                    continue;
                                }
                            }

                            // If no OU found, use the base DN with subtree search
                            if (searchBaseDn == _ldapSettings.BaseDn)
                            {
                                Console.WriteLine($"OU '{ouValue}' not found, using base DN with filter");
                                // Add OU filter to search within base DN
                                filterParts.Add($"(ou={Escape(ouValue)})");
                            }
                        }
                        else
                        {
                            // Already a DN
                            searchBaseDn = ouValue;
                        }

                        // Remove OU filter from regular filters
                        var filtersWithoutOu = new Dictionary<string, string>(reqBody.Filters);
                        filtersWithoutOu.Remove("ou");
                        reqBody.Filters = filtersWithoutOu;
                    }

                    // Build remaining filters
                    foreach (var (attribute, rawValue) in reqBody.Filters)
                    {
                        if (string.IsNullOrWhiteSpace(rawValue)) continue;

                        var attrLower = attribute.ToLowerInvariant();
                        // Handle department/status specially for OpenLDAP
                        if (_attributeMapper.IsOpenLdap &&
                            (attrLower == "department" || attrLower == "status" || attrLower == "accountstatus"))
                        {
                            // These use the description attribute for OpenLDAP
                            var formattedVal = _attributeMapper.FormatSearchValue(attribute, rawValue);
                            var escapedVal = Escape(formattedVal);
                            filterParts.Add($"(description={escapedVal})");
                            continue;
                        }

                        var ldapAttribute = _attributeMapper.MapAttribute(attribute);
                        var formattedValue = _attributeMapper.FormatSearchValue(attribute, rawValue);
                        var escapedValue = Escape(formattedValue);

                        if (rawValue == "*")
                        {
                            filterParts.Add($"({ldapAttribute}=*)");
                        }
                        else if (rawValue.Contains("*"))
                        {
                            // Handle wildcards - escape the asterisk
                            var wildcardEscaped = EscapeWildcard(rawValue);
                            filterParts.Add($"({ldapAttribute}={wildcardEscaped})");
                        }
                        else
                        {
                            filterParts.Add($"({ldapAttribute}={escapedValue})");
                        }
                    }
                }

                // Build final LDAP filter
                string ldapFilter;
                if (filterParts.Count == 1)
                {
                    ldapFilter = filterParts[0];
                }
                else if (filterParts.Count > 1)
                {
                    ldapFilter = $"(&{string.Join("", filterParts)})";
                }
                else
                {
                    ldapFilter = _attributeMapper.GetUserSearchFilter();
                }

                Console.WriteLine($"LDAP Search - BaseDN: {searchBaseDn}, Filter: {ldapFilter}");

                // Prepare attributes to retrieve
                var requestedAttributes = new HashSet<string>
                {
                    "distinguishedName",
                    _attributeMapper.GetUsernameSearchAttribute(),
                    _attributeMapper.GetEmailSearchAttribute(),
                    _attributeMapper.MapAttribute("DisplayName")
                };

                // Add requested attributes
                if (reqBody.Attributes != null && reqBody.Attributes.Any())
                {
                    foreach (var attr in reqBody.Attributes)
                    {
                        var attrLower = attr.ToLowerInvariant();

                        // For OpenLDAP, include description if department or status is requested
                        if (_attributeMapper.IsOpenLdap &&
                            (attrLower == "department" || attrLower == "status" || attrLower == "accountstatus"))
                        {
                            requestedAttributes.Add("description");
                        }
                        else if (attrLower == "department" && _attributeMapper.IsActiveDirectory)
                        {
                            requestedAttributes.Add(_attributeMapper.MapAttribute("Department"));
                        }
                        else if ((attrLower == "status" || attrLower == "accountstatus") && _attributeMapper.IsActiveDirectory)
                        {
                            requestedAttributes.Add(_attributeMapper.MapAttribute("AccountStatus"));
                        }
                        else
                        {
                            var ldapAttr = _attributeMapper.MapAttribute(attr);
                            requestedAttributes.Add(ldapAttr);
                        }
                    }
                }

                // LDAP search request
                var request = new SearchRequest(
                    searchBaseDn,
                    ldapFilter,
                    SearchScope.Subtree,
                    requestedAttributes.ToArray()
                )
                {
                    SizeLimit = Math.Max(reqBody.MaxResults, 1)
                };

                try
                {
                    var response = (SearchResponse)connection.SendRequest(request);
                    var results = new List<DirectorySearchResult>();

                    foreach (SearchResultEntry entry in response.Entries)
                    {
                        var result = new DirectorySearchResult
                        {
                            DistinguishedName = entry.DistinguishedName
                        };

                        // Get username from appropriate attribute
                        var usernameAttr = _attributeMapper.GetUsernameSearchAttribute();
                        if (entry.Attributes.Contains(usernameAttr))
                        {
                            result.Username = entry.Attributes[usernameAttr][0]?.ToString() ?? "Unavailable";
                        }
                        else
                        {
                            // Fallback: extract from DN
                            result.Username = ExtractUsernameFromDn(entry.DistinguishedName);
                        }

                        // Process requested attributes or default ones
                        var attributesToProcess = reqBody.Attributes?.Any() == true
                            ? reqBody.Attributes
                            : new List<string> { "Username", "DisplayName", "Email" };

                        foreach (var attr in attributesToProcess)
                        {
                            var attrLower = attr.ToLowerInvariant();

                            // Special handling for department in OpenLDAP
                            if (attrLower == "department" && _attributeMapper.IsOpenLdap)
                            {
                                if (entry.Attributes.Contains("description"))
                                {
                                    var description = entry.Attributes["description"][0]?.ToString();
                                    var dept = ExtractValueFromDescription(description, "Department");
                                    result.Attributes[attr] = dept ?? "Unavailable";
                                }
                                else
                                {
                                    result.Attributes[attr] = "Unavailable";
                                }
                                continue;
                            }

                            // Special handling for status in OpenLDAP
                            if ((attrLower == "status" || attrLower == "accountstatus") && _attributeMapper.IsOpenLdap)
                            {
                                if (entry.Attributes.Contains("description"))
                                {
                                    var description = entry.Attributes["description"][0]?.ToString();
                                    var status = ExtractValueFromDescription(description, "Account Status")
                                              ?? ExtractValueFromDescription(description, "Status");
                                    result.Attributes[attr] = status ?? "Unknown";
                                }
                                else
                                {
                                    result.Attributes[attr] = "Unknown";
                                }
                                continue;
                            }

                            // Special handling for department in AD
                            if (attrLower == "department" && _attributeMapper.IsActiveDirectory)
                            {
                                var deptAttr = _attributeMapper.MapAttribute("Department");
                                if (entry.Attributes.Contains(deptAttr))
                                {
                                    result.Attributes[attr] = entry.Attributes[deptAttr][0]?.ToString() ?? "Unavailable";
                                }
                                else
                                {
                                    result.Attributes[attr] = "Unavailable";
                                }
                                continue;
                            }

                            // Special handling for status in AD
                            if ((attrLower == "status" || attrLower == "accountstatus") && _attributeMapper.IsActiveDirectory)
                            {
                                var statusAttr = _attributeMapper.MapAttribute("AccountStatus");
                                if (entry.Attributes.Contains(statusAttr))
                                {
                                    var statusValue = entry.Attributes[statusAttr][0]?.ToString();
                                    if (int.TryParse(statusValue, out int userAccountControl))
                                    {
                                        bool isEnabled = (userAccountControl & 2) == 0; // Account disabled flag
                                        result.Attributes[attr] = isEnabled ? "Active" : "Disabled";
                                    }
                                    else
                                    {
                                        result.Attributes[attr] = "Unknown";
                                    }
                                }
                                else
                                {
                                    result.Attributes[attr] = "Unknown";
                                }
                                continue;
                            }

                            // Map generic attribute to LDAP attribute
                            var ldapAttr = _attributeMapper.MapAttribute(attr);

                            if (entry.Attributes.Contains(ldapAttr))
                            {
                                var value = entry.Attributes[ldapAttr][0]?.ToString();
                                result.Attributes[attr] = string.IsNullOrWhiteSpace(value) ? "Unavailable" : value;
                            }
                            else
                            {
                                result.Attributes[attr] = "Unavailable";
                            }
                        }

                        results.Add(result);
                    }

                    return results;
                }
                catch (DirectoryOperationException ex) when (ex.Message.Contains("The object does not exist"))
                {
                    Console.WriteLine($"OU not found: {searchBaseDn}. Trying alternative search...");

                    // If OU not found, search from base DN with ou filter
                    if (searchBaseDn != _ldapSettings.BaseDn)
                    {
                        var ouFilter = $"(ou={Escape(searchBaseDn.Split(',')[0].Replace("ou=", ""))})";
                        var combinedFilter = $"(&{_attributeMapper.GetUserSearchFilter()}{ouFilter})";

                        var fallbackRequest = new SearchRequest(
                            _ldapSettings.BaseDn,
                            combinedFilter,
                            SearchScope.Subtree,
                            requestedAttributes.ToArray()
                        )
                        {
                            SizeLimit = Math.Max(reqBody.MaxResults, 1)
                        };

                        var fallbackResponse = (SearchResponse)connection.SendRequest(fallbackRequest);
                        var results = new List<DirectorySearchResult>();

                        foreach (SearchResultEntry entry in fallbackResponse.Entries)
                        {
                            var result = new DirectorySearchResult
                            {
                                DistinguishedName = entry.DistinguishedName,
                                Username = ExtractUsernameFromDn(entry.DistinguishedName)
                            };

                            // Process attributes similarly...
                            // (Add similar attribute processing logic here)

                            results.Add(result);
                        }

                        return results;
                    }

                    throw;
                }
            });
        }

        // Helper method to extract username from DN if specific attributes are missing
        private string ExtractUsernameFromDn(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return "Unavailable";

            var parts = dn.Split(',');
            foreach (var part in parts)
            {
                if (_attributeMapper.IsActiveDirectory)
                {
                    if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                        return part.Substring(3);
                }
                else
                {
                    if (part.StartsWith("uid=", StringComparison.OrdinalIgnoreCase))
                        return part.Substring(4);
                    if (part.StartsWith("cn=", StringComparison.OrdinalIgnoreCase))
                        return part.Substring(3);
                }
            }

            return dn;
        }

        // Helper method to extract value from description field
        private string? ExtractValueFromDescription(string? description, string key)
        {
            if (string.IsNullOrWhiteSpace(description)) return null;

            var parts = description.Split(';');
            foreach (var part in parts)
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith($"{key}:", StringComparison.OrdinalIgnoreCase))
                {
                    return trimmed.Substring(key.Length + 1).Trim();
                }
            }

            return null;
        }

        // Helper method to escape wildcards properly
        private string EscapeWildcard(string value)
        {
            // Simple wildcard handling - just escape the asterisk
            return value.Replace("*", "\\2a");
        }
        public async Task<IEnumerable<string>> GetUserGroupsAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() => {

                string usernameAttr = _attributeMapper.GetUsernameSearchAttribute();
                string emailAttr = _attributeMapper.GetEmailSearchAttribute();

                var searchFilter = username.Contains("@")
                        ? $"({emailAttr}={Escape(username)})"
                        : $"({usernameAttr}={Escape(username)})";

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    searchFilter,
                    SearchScope.Subtree,
                     _attributeMapper.MapAttribute("MemberOf")
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                if (entry == null)
                {
                    return Enumerable.Empty<string>();
                }

                // checks whether the user is 'member of any group' or not
                string memberOfAttr = _attributeMapper.MapAttribute("MemberOf");
                if (!entry.Attributes.Contains(memberOfAttr) || entry.Attributes[memberOfAttr] == null)
                {
                    return Enumerable.Empty<string>();
                }
                var groups = entry.Attributes[memberOfAttr]
                    .GetValues(typeof(string))
                    .Cast<string>()
                    .Select(dn => _attributeMapper.ExtractGroupNameFromDn(dn))
                    .Where(name => !string.IsNullOrEmpty(name))
                    .ToList();

                return groups;
            });
        }

        public async Task UpdateUserProfileAsync(string userDn, UpdateMyProfile profile)
        {
            await Task.Run(() =>
            {
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();
                var modifications = new List<DirectoryAttributeModification>();
                void ReplaceIfProvided(string attr, string? value)
                {
                    if (string.IsNullOrWhiteSpace(value)) return;

                    var mod = new DirectoryAttributeModification
                    {
                        Name = attr,
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    mod.Add(value);
                    modifications.Add(mod);
                }

                // Update display name (cn for OpenLDAP, displayName for AD)
                if (!string.IsNullOrWhiteSpace(profile.DisplayName))
                {
                    if (_attributeMapper.IsActiveDirectory)
                    {
                        ReplaceIfProvided("displayName", profile.DisplayName);
                        // Also update cn for consistency
                        ReplaceIfProvided("cn", profile.DisplayName);
                    }
                    else
                    {
                        ReplaceIfProvided("cn", profile.DisplayName);
                    }
                }

                // Update other attributes using mapped names
                ReplaceIfProvided(_attributeMapper.MapAttribute("Phone"), profile.TelephoneNumber);
                ReplaceIfProvided("streetAddress", profile.StreetAddress);
                ReplaceIfProvided("l", profile.City);
                ReplaceIfProvided("st", profile.State);
                ReplaceIfProvided("postalCode", profile.PostalCode);

                if (modifications.Any())
                {
                    var modifyRequest = new ModifyRequest(userDn, modifications.ToArray());
                    connection.SendRequest(modifyRequest);
                }

                if (!string.IsNullOrWhiteSpace(profile.NewPassword))
                {
                    // Validate password policy
                    ValidatePasswordPolicy(profile.NewPassword);

                    // Change password
                    ChangePassword(connection, userDn, profile.NewPassword);
                }

            });
        }

        private void ChangePassword(LdapConnection connection, string userDn, string newPassword)
        {
            try
            {
                var passwordAttribute = _attributeMapper.MapAttribute("Password");
                
                if (_attributeMapper.IsActiveDirectory)
                {
                    // Use unicodePwd with UTF-16LE encoding
                    ChangePasswordAD(connection, userDn, newPassword);
                }
                else
                {
                    // Use userPassword with SSHA hash
                    ChangePasswordOpenLDAP(connection, userDn, newPassword);
                }
            }
            catch (DirectoryOperationException ex)
            {
                throw new InvalidOperationException(
                    "Password does not meet domain password policy.",
                    ex
                );
            }
            catch (LdapException ex) when (ex.ErrorCode == 53) // LDAP_UNWILLING_TO_PERFORM
            {
                throw new InvalidOperationException(
                    "Password does not meet policy requirements (length, complexity, history).",
                    ex
                );
            }
        }

        private static void ChangePasswordOpenLDAP(LdapConnection connection, string userDn, string newPassword)
        {
            var hashedPassword = GenerateSSHAHash(newPassword);

            var mod = new DirectoryAttributeModification
            {
                Name = "userPassword",
                Operation = DirectoryAttributeOperation.Replace
            };
            mod.Add(hashedPassword);

            var request = new ModifyRequest(userDn, mod);
            connection.SendRequest(request);
        }

        private static void ChangePasswordAD(LdapConnection connection, string userDn, string newPassword)
        {
            try
            {
                // AD requires password to be enclosed in quotes and UTF-16LE encoded
                var quotedPassword = $"\"{newPassword}\"";
                var passwordBytes = Encoding.Unicode.GetBytes(quotedPassword);

                var mod = new DirectoryAttributeModification
                {
                    Name = "unicodePwd",
                    Operation = DirectoryAttributeOperation.Replace
                };
                mod.Add(passwordBytes); // Add as byte array for AD

                var request = new ModifyRequest(userDn, mod);
                connection.SendRequest(request);
            }
            catch (DirectoryOperationException ex)
            {
                Console.WriteLine($"AD password change failed: {ex.Message}");
                throw new InvalidOperationException(
                    $"Password does not meet AD policy requirements: {ex.Message}",
                    ex
                );
            }
            catch (LdapException ex) when (ex.ErrorCode == 53) // LDAP_UNWILLING_TO_PERFORM
            {
                Console.WriteLine($"AD password policy violation: {ex.Message}");
                throw new InvalidOperationException(
                    "Password does not meet Active Directory policy requirements (length, complexity, history).",
                    ex
                );
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error changing AD password: {ex.Message}");
                throw new InvalidOperationException($"Failed to set password: {ex.Message}", ex);
            }
        }

        public async Task<CreateUserResponse> CreateUserAsync(CreateUserCommand newUser)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

            // Generate username based on LDAP type
            string username;
            string userRdn; // RDN (Relative Distinguished Name)

            if (_attributeMapper.IsActiveDirectory)
            {
                username = GenerateSamAccountName(newUser.FullName);
            }
            else
            {
                username = GenerateUid(newUser.FullName);
            }


            // Check if user exists by username
            if (UserExistsByUid(connection, username))
            {
                throw new InvalidOperationException($"User '{username}' already exists.");
            }

            // Check if department OU exists
            string departmentOuDn;
            try
            {
                departmentOuDn = DetermineDepartmentOuDn(connection, newUser.Department);
                Console.WriteLine($"Using department OU: {departmentOuDn}");
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to find department OU: {ex.Message}");
            }

            userRdn = _attributeMapper.GetUserRdn(username);

            string? managerDn = null;
            if (!string.IsNullOrWhiteSpace(newUser.ManagerEmail))
            {
                managerDn = FindUserDn(connection, newUser.ManagerEmail);
                if (managerDn == null)
                {
                    throw new InvalidOperationException($"Manager user '{newUser.ManagerEmail}' does not exist.");
                }
            };

            if (!string.IsNullOrWhiteSpace(newUser.Country) && newUser.Country.Length != 2)
            {
                throw new InvalidOperationException(
                    "Country must be a 2-letter ISO code (e.g., IN, US, GB)."
                );
            }


            // Generate credentials
            var email = $"{username}@{_ldapSettings.Domain}";
            var userDn = $"{userRdn},{departmentOuDn}";
            var password = GenerateStrongPassword();

            // Prevent self-management
            if (managerDn != null && managerDn.Equals(userDn, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("A user cannot be their own manager.");
            }
            // Split name for attributes
            var nameParts = newUser.FullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var firstName = nameParts.Length > 0 ? nameParts[0] : "";
            var lastName = nameParts.Length > 1 ? nameParts[^1] : firstName;

            // Create base attributes based on LDAP type
            var attributes = new List<DirectoryAttribute>();

            if (_attributeMapper.IsActiveDirectory)
            {
                // AD Server
                attributes.Add(new DirectoryAttribute("objectClass", new[] { "top", "person", "organizationalPerson", "user" }));
                attributes.Add(new DirectoryAttribute("cn", newUser.FullName));
                attributes.Add(new DirectoryAttribute("name", newUser.FullName));
                attributes.Add(new DirectoryAttribute("givenName", firstName));
                attributes.Add(new DirectoryAttribute("sn", lastName));
                attributes.Add(new DirectoryAttribute("sAMAccountName", username));
                attributes.Add(new DirectoryAttribute("userPrincipalName", $"{username}@{_ldapSettings.Domain}"));
                attributes.Add(new DirectoryAttribute("mail", email));
                attributes.Add(new DirectoryAttribute("displayName", newUser.FullName));

                // Department handling for AD
                if (!string.IsNullOrWhiteSpace(newUser.Department))
                {
                    attributes.Add(new DirectoryAttribute("department", newUser.Department));
                }

                // Title
                if (!string.IsNullOrWhiteSpace(newUser.Title))
                {
                    attributes.Add(new DirectoryAttribute("title", newUser.Title));
                }

                // Telephone
                if (!string.IsNullOrWhiteSpace(newUser.TelephoneNumber))
                {
                    attributes.Add(new DirectoryAttribute("telephoneNumber", newUser.TelephoneNumber));
                }

                // Description (for department in OpenLDAP style, but AD Server can also use it too)
                attributes.Add(new DirectoryAttribute("description", $"Department: {newUser.Department}"));

                // Manager
                if (managerDn != null)
                {
                    attributes.Add(new DirectoryAttribute("manager", managerDn));
                }

                // Address attributes for AD
                if (!string.IsNullOrWhiteSpace(newUser.StreetAddress))
                {
                    attributes.Add(new DirectoryAttribute("streetAddress", newUser.StreetAddress));
                }
                if (!string.IsNullOrWhiteSpace(newUser.City))
                {
                    attributes.Add(new DirectoryAttribute("l", newUser.City)); // AD uses 'l' for city
                }
                if (!string.IsNullOrWhiteSpace(newUser.State))
                {
                    attributes.Add(new DirectoryAttribute("st", newUser.State)); // AD uses 'st' for state
                }
                if (!string.IsNullOrWhiteSpace(newUser.PostalCode))
                {
                    attributes.Add(new DirectoryAttribute("postalCode", newUser.PostalCode));
                }
                if (!string.IsNullOrWhiteSpace(newUser.Country))
                {
                    attributes.Add(new DirectoryAttribute("c", newUser.Country.ToUpper()));
                }

                // Initial userAccountControl - set as disabled initially
                attributes.Add(new DirectoryAttribute("userAccountControl", "514")); // 514 = Disabled account

            }
            else
            {
                // OpenLDAP
                attributes.Add(new DirectoryAttribute("objectClass", new[] { "top", "person", "organizationalPerson", "inetOrgPerson" }));
                attributes.Add(new DirectoryAttribute("cn", newUser.FullName));
                attributes.Add(new DirectoryAttribute("givenName", firstName));
                attributes.Add(new DirectoryAttribute("sn", lastName));
                attributes.Add(new DirectoryAttribute("uid", username));

                // Password for OpenLDAP (SSHA hash)
                var hashedPassword = GenerateSSHAHash(password);
                attributes.Add(new DirectoryAttribute("userPassword", hashedPassword));

                attributes.Add(new DirectoryAttribute("mail", email));

                // Department in description for OpenLDAP
                attributes.Add(new DirectoryAttribute("description", $"Department: {newUser.Department}"));

                // Title
                if (!string.IsNullOrWhiteSpace(newUser.Title))
                {
                    attributes.Add(new DirectoryAttribute("title", newUser.Title));
                }

                // Telephone
                if (!string.IsNullOrWhiteSpace(newUser.TelephoneNumber))
                {
                    attributes.Add(new DirectoryAttribute("telephoneNumber", newUser.TelephoneNumber));
                }

                // Manager
                if (managerDn != null)
                {
                    attributes.Add(new DirectoryAttribute("manager", managerDn));
                }

                // Address attributes for OpenLDAP
                if (!string.IsNullOrWhiteSpace(newUser.StreetAddress))
                {
                    attributes.Add(new DirectoryAttribute("streetAddress", newUser.StreetAddress));
                }
                if (!string.IsNullOrWhiteSpace(newUser.City))
                {
                    attributes.Add(new DirectoryAttribute("l", newUser.City));
                }
                if (!string.IsNullOrWhiteSpace(newUser.State))
                {
                    attributes.Add(new DirectoryAttribute("st", newUser.State));
                }
                if (!string.IsNullOrWhiteSpace(newUser.PostalCode))
                {
                    attributes.Add(new DirectoryAttribute("postalCode", newUser.PostalCode));
                }
                if (!string.IsNullOrWhiteSpace(newUser.Country))
                {
                    attributes.Add(new DirectoryAttribute("c", newUser.Country.ToUpper()));
                }
            }

            try
            {
                // Create the user account
                var addRequest = new AddRequest(userDn, attributes.ToArray());
                connection.SendRequest(addRequest);

                Console.WriteLine($"User account created: {userDn}");

                // Handle post-creation tasks based on LDAP type
                if (_attributeMapper.IsActiveDirectory)
                {
                    // AD: Set password and enable account
                    await Task.Delay(200); // Brief delay for AD replication

                    try
                    {
                        // Set password for AD account
                        ChangePasswordAD(connection, userDn, password);
                        Console.WriteLine($"Password set for AD user: {username}");

                        // Enable the AD account (512 = Normal enabled account)
                        var enableMod = new DirectoryAttributeModification
                        {
                            Name = "userAccountControl",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        enableMod.Add("512"); // Normal enabled account

                        connection.SendRequest(new ModifyRequest(userDn, enableMod));
                        Console.WriteLine($"AD account enabled: {username}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Warning: Failed to set password/enable AD account: {ex.Message}");
                        // Continue anyway - admin can fix manually
                    }
                }
                else
                {
                    // OpenLDAP: Account is already enabled with password set
                    Console.WriteLine($"OpenLDAP user created with password: {username}");
                }

                // For OpenLDAP, try to add additional attributes if needed
                if (!_attributeMapper.IsActiveDirectory)
                {
                    try
                    {
                        await Task.Delay(100);
                        UpdateUserAttributes(connection, userDn, newUser, managerDn);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Note: Additional attribute update failed (non-critical): {ex.Message}");
                    }
                }

                return new CreateUserResponse
                {
                    Username = username,
                    InitialPassword = password,
                    Email = email,
                    DistinguishedName = userDn
                };
            }
            catch (DirectoryOperationException ex)
            {
                Console.WriteLine($"First attempt failed: {ex.Message}");
                Console.WriteLine("Error details: " + ex.Response?.ErrorMessage);

                // For AD, try simpler approach
                if (_attributeMapper.IsActiveDirectory)
                {
                    Console.WriteLine("Trying minimal AD user creation...");

                    var minimalAttributes = new List<DirectoryAttribute>
                    {
                        new DirectoryAttribute("objectClass", new[] { "top", "person", "organizationalPerson", "user" }),
                        new DirectoryAttribute("cn", newUser.FullName),
                        new DirectoryAttribute("sn", lastName),
                        new DirectoryAttribute("sAMAccountName", username),
                        new DirectoryAttribute("userPrincipalName", $"{username}@{_ldapSettings.Domain}"),
                        new DirectoryAttribute("userAccountControl", "514") // Disabled initially
                    };

                    var retryRequest = new AddRequest(userDn, minimalAttributes.ToArray());
                    connection.SendRequest(retryRequest);
                    Console.WriteLine($"Minimal AD user created: {username}");

                    // Try to set password and enable
                    try
                    {
                        await Task.Delay(200);
                        ChangePasswordAD(connection, userDn, password);

                        var enableMod = new DirectoryAttributeModification
                        {
                            Name = "userAccountControl",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        enableMod.Add("512");
                        connection.SendRequest(new ModifyRequest(userDn, enableMod));

                        Console.WriteLine($"Minimal AD user password set and enabled: {username}");
                    }
                    catch (Exception innerEx)
                    {
                        Console.WriteLine($"Warning: Could not set password/enable minimal AD user: {innerEx.Message}");
                    }

                    return new CreateUserResponse
                    {
                        Username = username,
                        InitialPassword = password,
                        Email = $"{username}@{_ldapSettings.Domain}",
                        DistinguishedName = userDn
                    };
                }
                else
                {
                    // OpenLDAP fallback
                    Console.WriteLine("Trying with minimal OpenLDAP attributes...");

                    var minimalAttributes = new List<DirectoryAttribute>
                    {
                        new DirectoryAttribute("objectClass", new[] { "top", "person", "organizationalPerson", "inetOrgPerson" }),
                        new DirectoryAttribute("cn", newUser.FullName),
                        new DirectoryAttribute("sn", lastName),
                        new DirectoryAttribute("uid", username),
                        new DirectoryAttribute("userPassword", GenerateSSHAHash(password)),
                        new DirectoryAttribute("mail", email)
                    };

                    var retryRequest = new AddRequest(userDn, minimalAttributes.ToArray());
                    connection.SendRequest(retryRequest);

                    await Task.Delay(100);
                    UpdateUserAttributes(connection, userDn, newUser, managerDn);

                    return new CreateUserResponse
                    {
                        Username = username,
                        InitialPassword = password,
                        Email = email,
                        DistinguishedName = userDn
                    };
                }
            }
            catch (LdapException ex)
            {
                Console.WriteLine($"LDAP error creating user: {ex.Message} (Error code: {ex.ErrorCode})");
                throw new InvalidOperationException($"Failed to create user: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error creating user: {ex.Message}");
                throw new InvalidOperationException($"Failed to create user: {ex.Message}", ex);
            }
        }

        //-------------------------------------------------------------------------
        private string DetermineDepartmentOuDn(LdapConnection connection, string department)
        {
            if (string.IsNullOrWhiteSpace(department))
                throw new ArgumentException("Department name cannot be empty");

            Console.WriteLine($"Looking for department OU: '{department}'");

            if (_attributeMapper.IsActiveDirectory)
            {
                // AD: Try multiple possible OU structures
                var possiblePaths = new[]
                {
            // Standard AD structures
            $"OU={department},DC=corp,DC=local",
            $"OU={department},OU=Departments,DC=corp,DC=local",
            $"OU={department},OU=Employees,DC=corp,DC=local",
            // For smaller ADs, users might be in CN=Users
            $"CN=Users,DC=corp,DC=local",
            // Check if department exists as an OU anywhere
            SearchForOuAnywhere(connection, department)
        };

                foreach (var path in possiblePaths.Distinct().Where(p => !string.IsNullOrEmpty(p)))
                {
                    try
                    {
                        if (DepartmentOuExists(connection, path))
                        {
                            Console.WriteLine($"Found AD department at: {path}");
                            return path;
                        }
                    }
                    catch
                    {
                        // Try next path
                        continue;
                    }
                }

                throw new InvalidOperationException(
                    $"Department OU '{department}' not found in AD. " +
                    $"Tried locations: {string.Join(", ", possiblePaths.Where(p => !string.IsNullOrEmpty(p)))}");
            }
            else
            {
                // OpenLDAP: Standard structure
                var ouPath = $"ou={department},ou=Employees,dc=corp,dc=local";

                if (!DepartmentOuExists(connection, ouPath))
                {
                    throw new InvalidOperationException(
                        $"Department OU '{department}' not found in OpenLDAP. " +
                        $"Expected: {ouPath}");
                }

                return ouPath;
            }
        }

        private string? SearchForOuAnywhere(LdapConnection connection, string ouName)
        {
            try
            {
                var searchRequest = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(&(objectClass=organizationalUnit)(|(ou={Escape(ouName)})(name={Escape(ouName)})))",
                    SearchScope.Subtree,
                    "distinguishedName"
                );

                var response = (SearchResponse)connection.SendRequest(searchRequest);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();

                return entry?.DistinguishedName;
            }
            catch
            {
                return null;
            }
        }
        private bool UserExistsByUid(LdapConnection connection, string uid)
        {
            try
            {
                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(uid={Escape(uid)})",
                    SearchScope.Subtree,
                    "uid"
                );
                var response = (SearchResponse)connection.SendRequest(request);
                return response.Entries.Count > 0;
            }
            catch
            {
                return false;
            }
        }

        private bool DepartmentOuExists(LdapConnection connection, string ouDn)
        {
            try
            {
                var request = new SearchRequest(
                    ouDn,
                    _attributeMapper.GetOuSearchFilter(),
                    SearchScope.Base,
                    "ou"
                );
                var response = (SearchResponse)connection.SendRequest(request);
                return response.Entries.Count > 0;
            }
            catch
            {
                return false;
            }
        }
        private string GenerateUid(string fullName)
        {
            var baseUid = fullName.ToLower()
               .Replace(" ", ".", StringComparison.Ordinal)
               .Replace("'", "", StringComparison.Ordinal)
               .Replace(",", "", StringComparison.Ordinal);

            var uid = baseUid;
            int suffix = 1;

            using var connection = _ldapAuthenticator.BindAsServiceAccount();

            while (UserExistsByUid(connection, uid))
            {
                uid = $"{baseUid}{suffix}";
                suffix++;
            }

            return uid;
        }

        private void UpdateUserAttributes(LdapConnection connection, string userDn, CreateUserCommand newUser, string? managerDn)
        {
            var modifications = new List<DirectoryAttributeModification>();

            if (!string.IsNullOrWhiteSpace(newUser.Department))
            {
                var descMod = new DirectoryAttributeModification
                {
                    Name = "description",
                    Operation = DirectoryAttributeOperation.Replace
                };
                descMod.Add($"Department: {newUser.Department}");
                modifications.Add(descMod);
            }


            if (!string.IsNullOrWhiteSpace(newUser.Title))
            {
                var mod = new DirectoryAttributeModification
                {
                    Name = "title",
                    Operation = DirectoryAttributeOperation.Replace
                };
                mod.Add(newUser.Title);
                modifications.Add(mod);
            }

            if (!string.IsNullOrWhiteSpace(newUser.TelephoneNumber))
            {
                var mod = new DirectoryAttributeModification
                {
                    Name = "telephoneNumber",
                    Operation = DirectoryAttributeOperation.Replace
                };
                mod.Add(newUser.TelephoneNumber);
                modifications.Add(mod);
            }

            if (managerDn != null)
            {
                var mod = new DirectoryAttributeModification
                {
                    Name = "manager",
                    Operation = DirectoryAttributeOperation.Replace
                };
                mod.Add(managerDn);
                modifications.Add(mod);
            }

            if (modifications.Count > 0)
            {
                var modifyRequest = new ModifyRequest(userDn, modifications.ToArray());
                connection.SendRequest(modifyRequest);
            }
        }

        private bool ValidatePasswordPolicy(string password)
        {
            if (password.Length < 8)
            {
                throw new InvalidOperationException("Password must be at least 8 characters long.");
            }

            return true;
        }

        private static string GenerateSSHAHash(string password)
        {
            using (var sha = System.Security.Cryptography.SHA1.Create())
            {
                // Generate random salt (4-8 bytes typical)
                var salt = new byte[4];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                // Combine password and salt
                var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
                var saltedPassword = new byte[passwordBytes.Length + salt.Length];
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, 0, passwordBytes.Length);
                Buffer.BlockCopy(salt, 0, saltedPassword, passwordBytes.Length, salt.Length);

                // Compute hash
                var hash = sha.ComputeHash(saltedPassword);

                // Combine hash and salt for SSHA format
                var hashWithSalt = new byte[hash.Length + salt.Length];
                Buffer.BlockCopy(hash, 0, hashWithSalt, 0, hash.Length);
                Buffer.BlockCopy(salt, 0, hashWithSalt, hash.Length, salt.Length);

                return "{SSHA}" + Convert.ToBase64String(hashWithSalt);
            }
        }
        private static string GenerateStrongPassword()
        {
            // Define simple sets
            string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // Removed 'I', 'O' to avoid confusion
            string lower = "abcdefghijkmnopqrstuvwxyz"; // Removed 'l'
            string digits = "23456789";                 // Removed '0', '1'
            string specials = "!@#$%^&*";

            var random = new Random();

            // 1. Force one from each to satisfy "3 of 4" categories rule
            var chars = new List<char>
            {
                upper[random.Next(upper.Length)],
                lower[random.Next(lower.Length)],
                digits[random.Next(digits.Length)],
                specials[random.Next(specials.Length)]
            };

            // 2. Fill the rest to reach 12 characters (Recommended length)
            string all = upper + lower + digits + specials;
            for (int i = 0; i < 8; i++)
                chars.Add(all[random.Next(all.Length)]);

            // 3. Shuffle so the patterns aren't predictable
            return new string(chars.OrderBy(x => random.Next()).ToArray());
        }

        private string? FindUserDn(LdapConnection connection, string email)
        {
            try
            {
                string emailAttribute = _attributeMapper.IsActiveDirectory
                           ? "userPrincipalName"
                           : "mail";

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"({emailAttribute}={Escape(email)})",
                    SearchScope.Subtree,
                    "distinguishedName"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                return response.Entries.Cast<SearchResultEntry>()
                    .FirstOrDefault()
                    ?.DistinguishedName;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error finding user by email '{email}': {ex.Message}");
                return null;
            }
        }

        private static string Escape(string value)
        {
            return value
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }

        public string GenerateSamAccountName(string fullName)
        {
            var baseName = fullName.Replace(" ", "").ToLower();
            var samAccountName = baseName;
            int suffix = 1;
            while (true)
            {
                var existingUser = GetByUsernameAsync(
                    _ldapAuthenticator.BindAsServiceAccount(),
                    samAccountName
                ).Result;
                if (existingUser == null)
                {
                    return samAccountName;
                }
                samAccountName = $"{baseName}{suffix}";
                suffix++;
            }
        }

        private string GetDepartmentOuDnAsync(LdapConnection connection, string department)
        {
            try
            {
                string objectClass = _attributeMapper.IsActiveDirectory
                        ? "organizationalUnit"
                        : "organizationalUnit";

                string nameAttribute = _attributeMapper.IsActiveDirectory
                           ? "name"  // AD often uses 'name' attribute
                           : "ou";   // OpenLDAP uses 'ou' attribute

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(&(objectClass={objectClass})(|({nameAttribute}={Escape(department)})(ou={Escape(department)})))",
                    SearchScope.Subtree,
                    "distinguishedName"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var ouEntry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                if (ouEntry == null) throw new InvalidOperationException("Department OU does not exist.");
                return ouEntry.DistinguishedName;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Error finding department OU '{department}': {ex.Message}", ex);
            }
        }

        public async Task UpdateUserAsAdminAsync(AdminUpdateUserCommand command)
        {
            await Task.Run(() =>
            {
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

                // 1️. Resolve user DN
                var userDn = FindUserDnByEmail(connection, command.Email) ?? throw new InvalidOperationException($"Target user with email '{command.Email}' not found.");

                // 2️. Handle department change: OU move
                string? newUserDn = null;
                var modifications = new List<DirectoryAttributeModification>();
                if (!string.IsNullOrWhiteSpace(command.Department))
                {
                    if (_attributeMapper.IsActiveDirectory)
                    {
                        var deptMod = new DirectoryAttributeModification
                        {
                            Name = "department",  // AD attribute name
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        deptMod.Add(command.Department);
                        modifications.Add(deptMod);

                        Console.WriteLine($"AD: Updating department attribute to '{command.Department}'");
                    }
                    else
                    {
                        try
                        {
                            var targetOuDn = GetDepartmentOuDnAsync(connection, command.Department);
                            // Check if we're already in the target OU
                            var currentParentDn = GetParentOuDn(userDn);
                            if (!string.Equals(currentParentDn, targetOuDn, StringComparison.OrdinalIgnoreCase))
                            {
                                MoveUserToOu(connection, userDn, targetOuDn);

                                // After move, DN changes: recompute
                                var uid = ExtractUidFromDn(userDn);
                                newUserDn = $"uid={uid},{targetOuDn}";

                                Console.WriteLine($"OpenLDAP: Moved user to OU '{targetOuDn}'");
                            }
                            else
                            {
                                Console.WriteLine($"OpenLDAP: User already in department OU '{targetOuDn}'");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Could not move user to department OU: {ex.Message}");
                        }
                    }
                }
                // Use new DN if user was moved
                var effectiveUserDn = newUserDn ?? userDn;

                if (!_attributeMapper.IsActiveDirectory)
                {
                    string currentDescription = "";
                    try
                    {
                        var searchRequest = new SearchRequest(
                            userDn,
                            "(objectClass=inetOrgPerson)",
                            SearchScope.Base,
                            "description"
                        );

                        var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                        var entry = searchResponse.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                        if (entry != null && entry.Attributes.Contains("description"))
                        {
                            currentDescription = entry.Attributes["description"][0]?.ToString() ?? "";
                        }
                    }
                    catch
                    {
                        Console.WriteLine($"Note: Could not retrieve description for {userDn}");
                    }

                    if (!string.IsNullOrWhiteSpace(command.Department) || !string.IsNullOrWhiteSpace(currentDescription))
                    {
                        // Parse current description attributes
                        var descriptionAttributes = ParseDescriptionAttributes(currentDescription);

                        // Update department if provided
                        if (!string.IsNullOrWhiteSpace(command.Department))
                        {
                            descriptionAttributes["Department"] = command.Department;
                        }

                        var newDescriptionParts = new List<string>();

                        // Add department if exists
                        if (descriptionAttributes.TryGetValue("Department", out var department))
                        {
                            newDescriptionParts.Add($"Department: {department}");
                        }

                        // Preserve account status if exists
                        if (descriptionAttributes.TryGetValue("Account Status", out var accountStatus))
                        {
                            newDescriptionParts.Add($"Account Status: {accountStatus}");
                        }
                        else if (descriptionAttributes.TryGetValue("Status", out var altStatus))
                        {
                            newDescriptionParts.Add($"Account Status: {altStatus}");
                        }
                        else if (newDescriptionParts.Any())
                        {
                            // Only add default if we're creating a description
                            newDescriptionParts.Add("Account Status: Active");
                        }

                        // Add other preserved attributes (excluding those already handled)
                        foreach (var kvp in descriptionAttributes)
                        {
                            if (kvp.Key.Equals("Department", StringComparison.OrdinalIgnoreCase) ||
                                kvp.Key.Equals("Account Status", StringComparison.OrdinalIgnoreCase) ||
                                kvp.Key.Equals("Status", StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            if (!string.IsNullOrWhiteSpace(kvp.Value))
                            {
                                newDescriptionParts.Add($"{kvp.Key}: {kvp.Value}");
                            }
                        }

                        // Only update description if we have content
                        if (newDescriptionParts.Any())
                        {
                            string newDescription = string.Join("; ", newDescriptionParts);

                            var descMod = new DirectoryAttributeModification
                            {
                                Name = "description",
                                Operation = DirectoryAttributeOperation.Replace
                            };
                            descMod.Add(newDescription);
                            modifications.Add(descMod);

                            Console.WriteLine($"OpenLDAP: Updated description: {newDescription}");
                        }

                    }
                }

                if (!string.IsNullOrWhiteSpace(command.Title))
                {
                    var mod = new DirectoryAttributeModification
                    {
                        Name = "title",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    mod.Add(command.Title);
                    modifications.Add(mod);
                }

                // 3️. Manager assignment
                if (!string.IsNullOrWhiteSpace(command.ManagerEmail))
                {
                    var managerDn = FindUserDnByEmail(connection, command.ManagerEmail)
                        ?? throw new InvalidOperationException("Manager not found.");

                    if (string.Equals(managerDn, effectiveUserDn, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("User cannot be their own manager.");

                    var mod = new DirectoryAttributeModification
                    {
                        Name = "manager",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    mod.Add(managerDn);
                    modifications.Add(mod);
                }
                

                if (modifications.Any())
                {
                    try
                    {
                        connection.SendRequest(new ModifyRequest(effectiveUserDn, modifications.ToArray()));
                        Console.WriteLine($"Successfully applied {modifications.Count} updates to {effectiveUserDn}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error applying modifications: {ex.Message}");
                        throw new InvalidOperationException($"Failed to update user: {ex.Message}", ex);
                    }
                }
                else
                {
                    Console.WriteLine($"No modifications to apply for {userDn}");
                }
            });
        }

        private bool IsWithinAllowedParent(string dn)
        {
            var allowedParents = new[]
            {
                "ou=Employees,dc=corp,dc=local"
            };

            var normalizedDn = dn.Trim().ToLower();

            foreach (var allowedParent in allowedParents)
            {
                var normalizedParent = allowedParent.Trim().ToLower();

                // Check if DN is exactly the allowed parent or is a child of it
                if (normalizedDn == normalizedParent ||
                    normalizedDn.EndsWith("," + normalizedParent))
                {
                    return true;
                }
            }

            return false;
        }

        private static string ExtractUidFromDn(string userDn)
        {
            if (string.IsNullOrEmpty(userDn))
                return string.Empty;

            var rdn = userDn.Split(',')[0];
            if (rdn.StartsWith("uid=", StringComparison.OrdinalIgnoreCase)) return rdn.Substring(4); // Remove "uid="
            if (rdn.StartsWith("cn=", StringComparison.OrdinalIgnoreCase)) return rdn.Substring(3); // Remove "cn="
            return rdn;
        }

        private string? FindUserDnByEmail(LdapConnection connection, string email)
        {
            try
            {
                string emailAttribute = _attributeMapper.IsActiveDirectory
                        ? "userPrincipalName"  // AD uses UPN
                        : "mail";

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"({emailAttribute}={Escape(email)})",
                    SearchScope.Subtree,
                    "distinguishedName"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                return response.Entries.Cast<SearchResultEntry>().FirstOrDefault()?.DistinguishedName;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error finding user by email '{email}': {ex.Message}");
                return null;
            }
        }
        private static string GetParentOuDn(string userDn)
        {
            var index = userDn.IndexOf(",");
            if (index == -1) throw new InvalidOperationException("Invalid DN format.");

            return userDn.Substring(index + 1);
        }
        private void MoveUserToOu(LdapConnection connection, string userDn, string targetOuDn)
        {
            var currentParentDn = GetParentOuDn(userDn);

            // If already in target OU → do nothing
            if (string.Equals(currentParentDn, targetOuDn, StringComparison.OrdinalIgnoreCase)) return;

            var rdn = userDn.Split(',')[0];

            var request = new ModifyDNRequest(userDn, targetOuDn, rdn)
            {
                DeleteOldRdn = true
            };

            connection.SendRequest(request);
        }

        public async Task UpdateUserStatusAsync(UpdateUserStatusCommand command)
        {
            await Task.Run(() =>
            {
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

                var userDn = FindUserDn(connection, command.Email)
                    ?? throw new InvalidOperationException($"User with email '{command.Email}' not found.");

                if (_attributeMapper.IsActiveDirectory && _attributeMapper.UseAdAccountControl)
                {
                    var adValue = _attributeMapper.GetAdAccountControlValue(command.IsEnabled);

                    var mod = new DirectoryAttributeModification
                    {
                        Name = "userAccountControl",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    mod.Add(adValue);

                    connection.SendRequest(new ModifyRequest(userDn, mod));
                }
                else
                {
                    // First, get current description
                    var searchRequest = new SearchRequest(
                    userDn,
                    "(objectClass=inetOrgPerson)",
                    SearchScope.Base,
                    "description"
                    );
                    var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                    var entry = searchResponse.Entries.Cast<SearchResultEntry>().FirstOrDefault()
                        ?? throw new InvalidOperationException("User not found.");

                    string currentDescription = "";
                    if (entry != null && entry.Attributes.Contains("description"))
                    {
                        currentDescription = entry.Attributes["description"][0]?.ToString() ?? "";
                    }

                    var descriptionAttributes = ParseDescriptionAttributes(currentDescription);

                    string newDescription = BuildDescriptionString(descriptionAttributes, command.IsEnabled);

                    var mod = new DirectoryAttributeModification
                    {
                        Name = "description",
                        Operation = DirectoryAttributeOperation.Replace
                        //Operation = command.IsEnabled
                        //            ? DirectoryAttributeOperation.Delete  // Remove lock
                        //            : DirectoryAttributeOperation.Replace // Set lock (000001010000Z means locked)
                    };
                    mod.Add(newDescription);
                    try
                    {
                        connection.SendRequest(new ModifyRequest(userDn, mod));
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error updating user status: {ex.Message}");
                        throw;
                    }
                }
            });
        }

        private string BuildDescriptionString(Dictionary<string, string> attributes, bool isEnabled)
        {
            // Create a copy to avoid modifying the original
            var attrCopy = new Dictionary<string, string>(attributes, StringComparer.OrdinalIgnoreCase);

            attrCopy["Account Status"] = isEnabled ? "Active" : "Disabled";

            // Remove old "Status" key if present
            if (attrCopy.ContainsKey("Status"))
            {
                attrCopy.Remove("Status");
            }

            var descriptionParts = new List<string>();

            // Add prioritized attributes first
            var priorityAttributes = new[] { "Department", "Account Status" };

            foreach (var priorityKey in priorityAttributes)
            {
                if (attrCopy.TryGetValue(priorityKey, out var value))
                {
                    descriptionParts.Add($"{priorityKey}: {value}");
                    attrCopy.Remove(priorityKey);
                }
            }

            // Add remaining attributes in alphabetical order
            var remainingKeys = attrCopy.Keys.OrderBy(k => k).ToList();
            foreach (var key in remainingKeys)
            {
                descriptionParts.Add($"{key}: {attrCopy[key]}");
            }

            return string.Join("; ", descriptionParts);
        }

        public async Task CreateOuAsync(CreateOuCommand command)
        {
            await Task.Run(() =>
            {
                //var connection = _ldapAuthenticator.BindAsInfraServiceAccountForWrite();

                var connection = _ldapAuthenticator.BindAsInfraServiceAccountForWrite();
                if (string.IsNullOrWhiteSpace(command.NewOuName))
                {
                    throw new InvalidOperationException("OU name is required");
                }

                // Validate OU name
                if (command.NewOuName.Any(c => "\\,+\"<>;=".Contains(c)))
                {
                    throw new InvalidOperationException("OU name contains invalid characters");
                }

                // Check if parent is within allowed hierarchy
                if (!IsWithinAllowedParent(command.ParentOuDn))
                {
                    throw new InvalidOperationException(
                        $"Security Violation: Parent OU must be within allowed hierarchy. " +
                        $"Allowed: ou=Employees,dc=corp,dc=local");
                }

                // 3. Parent Existence Check: Verify the parent actually exists in AD
                var parentCheckRequest = new SearchRequest(
                    command.ParentOuDn,
                    "(objectClass=*)",
                    SearchScope.Base, // Base scope checks only the object itself
                    "distinguishedName"
                );

                try
                {
                    connection.SendRequest(parentCheckRequest);
                }
                catch (DirectoryOperationException)
                {
                    throw new InvalidOperationException($"The parent OU '{command.ParentOuDn}' does not exist.");
                }

                // Duplicate Check
                var existOuRequest = new SearchRequest(
                    command.ParentOuDn,
                    $"ou={Escape(command.NewOuName)}",
                    SearchScope.OneLevel,
                    "ou"
                );

                var existOuResponse = (SearchResponse)connection.SendRequest(existOuRequest);
                if (existOuResponse.Entries.Count > 0) throw new InvalidOperationException("OU with same name already exists");

                var ouDn = $"ou={command.NewOuName},{command.ParentOuDn}";
                var attributes = new DirectoryAttribute[]
                {
                    new DirectoryAttribute("objectClass", "organizationalUnit"),
                    new DirectoryAttribute("ou", command.NewOuName)
                };

                var addRequest = new AddRequest(ouDn, attributes);
                connection.SendRequest(addRequest);
            });
        }

        public async Task DeleteOuAsync(DeleteOuCommand command)
        {
            await Task.Run(() =>
            {
                //var connection = _ldapAuthenticator.BindAsInfraServiceAccountForWrite();
                var connection = _ldapAuthenticator.BindAsInfraServiceAccountForWrite();
                
                // Check if trying to delete critical OU
                var criticalOus = new[]
                {
                    "ou=Employees,dc=corp,dc=local",
                    "dc=corp,dc=local"
                };
                var normalizedOuDn = command.OuDn.Trim().ToLower();
                foreach (var criticalOu in criticalOus)
                {
                    if (normalizedOuDn == criticalOu.ToLower())
                    {
                        throw new InvalidOperationException(
                            $"Cannot delete critical organizational unit: {criticalOu}");
                    }
                }

                // Check for child objects
                var childRequest = new SearchRequest(
                    command.OuDn,
                    "(objectClass=*)",
                    SearchScope.OneLevel,
                    "distinguishedName"
                );
                var childResponse = (SearchResponse)connection.SendRequest(childRequest);

                if (childResponse.Entries.Count > 0 && !command.CascadeDelete)
                {
                    throw new InvalidOperationException(
                        "OU contains child objects. Enable CascadeDelete to proceed."
                    );
                }

                if (command.CascadeDelete)
                {
                    DeleteChildrenRecursively(connection, command.OuDn);
                }

                // Delete the OU itself
                connection.SendRequest(new DeleteRequest(command.OuDn));
            });
        }
        private void DeleteChildrenRecursively(LdapConnection connection, string parentDn)
        {
            var searchRequest = new SearchRequest(
                parentDn,
                "(objectClass=*)",
                SearchScope.OneLevel,
                "distinguishedName", "objectClass"
            );

            var response = (SearchResponse)connection.SendRequest(searchRequest);

            // Count objects by type for logging
            int userCount = 0, ouCount = 0, otherCount = 0;

            foreach (SearchResultEntry entry in response.Entries)
            {
                if (entry.Attributes.Contains("objectClass"))
                {
                    var objectClasses = entry.Attributes["objectClass"].GetValues(typeof(string))
                        .Cast<string>().Select(s => s.ToLower()).ToList();

                    if (objectClasses.Contains("organizationalunit"))
                        ouCount++;
                    else if (objectClasses.Contains("inetorgperson") || objectClasses.Contains("person"))
                        userCount++;
                    else
                        otherCount++;
                }
                else
                {
                    otherCount++;
                }

                DeleteChildrenRecursively(connection, entry.DistinguishedName);

                connection.SendRequest(new DeleteRequest(entry.DistinguishedName));
            }

            if (response.Entries.Count > 0)
            {
                Console.WriteLine($"Deleted from {parentDn}: {userCount} users, {ouCount} OUs, {otherCount} other objects");
            }
        }

    }
}
