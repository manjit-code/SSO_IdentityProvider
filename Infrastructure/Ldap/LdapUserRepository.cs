using Microsoft.Extensions.Options;
using Esyasoft.Ldap.Gateway.Domain.Entities;
using Esyasoft.Ldap.Gateway.Domain.Interfaces;
using Esyasoft.Ldap.Gateway.Infrastructure.Configuration;
using Esyasoft.Ldap.Gateway.Infrastructure.Mapper;
using Esyasoft.Ldap.Gateway.Infrastructure.Security;
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

namespace Esyasoft.Ldap.Gateway.Infrastructure.Ldap
{
    public class LdapUserRepository : IUserRepository
    {
        private readonly LdapSettings _ldapSettings;
        private readonly ILdapAuthenticator _ldapAuthenticator;
        private readonly AttributeMapper _attributeMapper;
        private readonly PasswordPolicyValidator _passwordPolicyValidator;

        public LdapUserRepository(IOptions<LdapSettings> option, ILdapAuthenticator ldapAuthenticator, AttributeMapper attributeMapper, PasswordPolicyValidator passwordPolicyValidator)
        {
            _ldapSettings = option.Value;
            _ldapAuthenticator = ldapAuthenticator;
            _attributeMapper = attributeMapper;
            _passwordPolicyValidator = passwordPolicyValidator;
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
                    Department = department,
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

                        // Handle ManagerEmail specially - need to search by manager's DN
                        if (attrLower == "manageremail")
                        {
                            // First, find the manager's DN by email
                            string? managerDn = FindUserDnByEmail(connection, rawValue);
                            if (!string.IsNullOrEmpty(managerDn))
                            {
                                // Escape the DN for LDAP filter
                                var escapedDn = Escape(managerDn);
                                filterParts.Add($"(manager={escapedDn})");
                            }
                            else
                            {
                                // If manager not found, add a filter that will return no results
                                filterParts.Add("(manager=non-existent-manager)");
                            }
                            continue;
                        }

                        // Handle department/status specially for OpenLDAP
                        if (_attributeMapper.IsOpenLdap && (attrLower == "department" || attrLower == "status" || attrLower == "accountstatus"))
                        {
                            var formattedVal = _attributeMapper.FormatSearchValue(attribute, rawValue);
                            var escapedVal = Escape(formattedVal);

                            // For status, use wildcard search in description
                            if (attrLower == "status" || attrLower == "accountstatus")
                            {
                                filterParts.Add($"(description=*{escapedVal}*)");
                            }
                            else // department
                            {
                                filterParts.Add($"(description=*Department: {escapedVal}*)");
                            }
                            continue;
                        }

                        // Handle address fields for both AD and OpenLDAP
                        if (attrLower == "city" || attrLower == "state" || attrLower == "postalcode" || attrLower == "country" || attrLower == "streetaddress")
                        {
                            // Capitalize the first letter for the description format
                            string fieldName = char.ToUpper(attrLower[0]) + attrLower.Substring(1);
                            if (fieldName == "Postalcode") fieldName = "PostalCode";
                            if (fieldName == "Streetaddress") fieldName = "Street";

                            filterParts.Add($"(description=*{fieldName}: {Escape(rawValue)}*)");
                            Console.WriteLine($"Added description filter: {fieldName}: {rawValue}");
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

                        if (attrLower == "distinguishedname" || attrLower == "description")
                        {
                            continue;
                        }
                        else if (attrLower == "streetaddress" || attrLower == "city" || attrLower == "state" || attrLower == "postalcode" || attrLower == "country")
                        {
                            if (!_attributeMapper.IsOpenLdap)
                            {
                                var ldapAttr = _attributeMapper.MapAttribute(attr);
                                requestedAttributes.Add(ldapAttr);
                            }
                        }
                        else
                        {
                            var ldapAttr = _attributeMapper.MapAttribute(attr);
                            requestedAttributes.Add(ldapAttr);
                        }
                    }
                }

                // include description for OpenLdap to extract data, will not be in response
                if (_attributeMapper.IsOpenLdap && !requestedAttributes.Contains("description"))
                {
                    requestedAttributes.Add("description");
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

                            // Handle DistinguishedName specially
                            if (attrLower == "distinguishedname")
                            {
                                result.Attributes[attr] = entry.DistinguishedName;
                                continue;
                            }

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

                                    // Default to "Active" if no status found
                                    result.Attributes[attr] = !string.IsNullOrEmpty(status) ? status : "Active";
                                }
                                else
                                {
                                    result.Attributes[attr] = "Active";
                                }
                                continue;
                            }

                            // Handle address attributes
                            if (attrLower == "streetaddress" || attrLower == "city" || attrLower == "state" ||
                                attrLower == "postalcode" || attrLower == "country")
                            {
                                if (_attributeMapper.IsOpenLdap)
                                {
                                    // For OpenLDAP, get from description
                                    if (entry.Attributes.Contains("description"))
                                    {
                                        var description = entry.Attributes["description"][0]?.ToString();
                                        var descriptionAttrs = ParseDescriptionAttributes(description);

                                        string fieldKey = attrLower switch
                                        {
                                            "streetaddress" => "Street",
                                            "city" => "City",
                                            "state" => "State",
                                            "postalcode" => "PostalCode",
                                            "country" => "Country",
                                            _ => attr
                                        };

                                        Console.WriteLine($"Looking for {fieldKey} in description: {description}");

                                        if (descriptionAttrs.TryGetValue(fieldKey, out var value))
                                        {
                                            result.Attributes[attr] = value;
                                            Console.WriteLine($"Found {fieldKey}: {value}");
                                        }
                                        else
                                        {
                                            result.Attributes[attr] = "Not provided";
                                            Console.WriteLine($"Did not find {fieldKey} in description");
                                        }
                                    }
                                    else
                                    {
                                        result.Attributes[attr] = "Not provided";
                                    }
                                }
                                else
                                {
                                    // For AD, use direct attributes
                                    string ldapAttribute = _attributeMapper.MapAttribute(attr);
                                    if (entry.Attributes.Contains(ldapAttribute))
                                    {
                                        var value = entry.Attributes[ldapAttribute][0]?.ToString();
                                        result.Attributes[attr] = string.IsNullOrWhiteSpace(value) ? "Not provided" : value;
                                    }
                                    else
                                    {
                                        result.Attributes[attr] = "Not provided";
                                    }
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
                                        result.Attributes[attr] = "Active";
                                    }
                                }
                                else
                                {
                                    result.Attributes[attr] = "Active";
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
                                DistinguishedName = entry.DistinguishedName
                            };

                            // Get username
                            var usernameAttr = _attributeMapper.GetUsernameSearchAttribute();
                            if (entry.Attributes.Contains(usernameAttr))
                            {
                                result.Username = entry.Attributes[usernameAttr][0]?.ToString() ?? "Unavailable";
                            }
                            else
                            {
                                result.Username = ExtractUsernameFromDn(entry.DistinguishedName);
                            }

                            // Process attributes using the same logic as main search
                            var attributesToProcess = reqBody.Attributes?.Any() == true
                                ? reqBody.Attributes
                                : new List<string> { "Username", "DisplayName", "Email" };

                            foreach (var attr in attributesToProcess)
                            {
                                var attrLower = attr.ToLowerInvariant();

                                if (attrLower == "distinguishedname")
                                {
                                    result.Attributes[attr] = entry.DistinguishedName;
                                    continue;
                                }

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

                                if ((attrLower == "status" || attrLower == "accountstatus") && _attributeMapper.IsOpenLdap)
                                {
                                    if (entry.Attributes.Contains("description"))
                                    {
                                        var description = entry.Attributes["description"][0]?.ToString();
                                        var status = ExtractValueFromDescription(description, "Account Status")
                                                  ?? ExtractValueFromDescription(description, "Status");
                                        result.Attributes[attr] = !string.IsNullOrEmpty(status) ? status : "Active";
                                    }
                                    else
                                    {
                                        result.Attributes[attr] = "Active";
                                    }
                                    continue;
                                }

                                // Handle address attributes - extract from description for OpenLDAP
                                if (attrLower == "streetaddress" || attrLower == "city" || attrLower == "state" ||
                                    attrLower == "postalcode" || attrLower == "country")
                                {
                                    if (_attributeMapper.IsOpenLdap)
                                    {
                                        // For OpenLDAP, get from description
                                        if (entry.Attributes.Contains("description"))
                                        {
                                            var description = entry.Attributes["description"][0]?.ToString();
                                            var descriptionAttrs = ParseDescriptionAttributes(description);

                                            string fieldKey = attrLower switch
                                            {
                                                "streetaddress" => "Street",
                                                "city" => "City",
                                                "state" => "State",
                                                "postalcode" => "PostalCode",
                                                "country" => "Country",
                                                _ => attr
                                            };

                                            if (descriptionAttrs.TryGetValue(fieldKey, out var value))
                                            {
                                                result.Attributes[attr] = value;
                                            }
                                            else
                                            {
                                                result.Attributes[attr] = "Not provided";
                                            }
                                        }
                                        else
                                        {
                                            result.Attributes[attr] = "Not provided";
                                        }
                                    }
                                    else
                                    {
                                        string ldapAttribute = _attributeMapper.MapAttribute(attr);
                                        if (entry.Attributes.Contains(ldapAttribute))
                                        {
                                            var value = entry.Attributes[ldapAttribute][0]?.ToString();
                                            result.Attributes[attr] = string.IsNullOrWhiteSpace(value) ? "Not provided" : value;
                                        }
                                        else
                                        {
                                            result.Attributes[attr] = "Not provided";
                                        }
                                    }
                                    continue;
                                }
                                // Default handling for other attributes
                                var ldapAttrGeneric = _attributeMapper.MapAttribute(attr);
                                if (entry.Attributes.Contains(ldapAttrGeneric))
                                {
                                    var value = entry.Attributes[ldapAttrGeneric][0]?.ToString();
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

                    throw;
                }
            });
        }

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
        private string EscapeWildcard(string value)
        {
            // Simple wildcard handling - just escape the asterisk
            return value.Replace("*", "\\2a");
        }
        public async Task<IEnumerable<string>> GetUserGroupsAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() =>
            {

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

                // For OpenLDAP, we need to update the description
                if (_attributeMapper.IsOpenLdap)
                {
                    // First, get current description
                    var searchRequest = new SearchRequest(
                        userDn,
                        "(objectClass=inetOrgPerson)",
                        SearchScope.Base,
                        "description", "title", "telephoneNumber", "manager"
                    );

                    var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                    var entry = searchResponse.Entries.Cast<SearchResultEntry>().FirstOrDefault();

                    if (entry == null) throw new InvalidOperationException("User not found");

                    // Parse current description
                    string currentDescription = entry.Attributes.Contains("description")
                        ? entry.Attributes["description"][0]?.ToString() ?? ""
                        : "";

                    var descriptionAttrs = ParseDescriptionAttributes(currentDescription);

                    if (!string.IsNullOrWhiteSpace(profile.DisplayName))
                    {
                        var mod = new DirectoryAttributeModification
                        {
                            Name = "cn",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        mod.Add(profile.DisplayName);
                        modifications.Add(mod);
                    }

                    if (!string.IsNullOrWhiteSpace(profile.TelephoneNumber))
                    {
                        var mod = new DirectoryAttributeModification
                        {
                            Name = "telephoneNumber",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        mod.Add(profile.TelephoneNumber);
                        modifications.Add(mod);
                    }

                    // Update description attributes
                    if (!string.IsNullOrWhiteSpace(profile.StreetAddress))
                        descriptionAttrs["Street"] = profile.StreetAddress;

                    if (!string.IsNullOrWhiteSpace(profile.City))
                        descriptionAttrs["City"] = profile.City;

                    if (!string.IsNullOrWhiteSpace(profile.State))
                        descriptionAttrs["State"] = profile.State;

                    if (!string.IsNullOrWhiteSpace(profile.PostalCode))
                        descriptionAttrs["PostalCode"] = profile.PostalCode;

                    if (!string.IsNullOrWhiteSpace(profile.Country))
                    {
                        string countryName = profile.Country.ToUpper() switch
                        {
                            "IN" => "India",
                            "US" => "United States",
                            "UK" => "United Kingdom",
                            "CA" => "Canada",
                            "AU" => "Australia",
                            "DE" => "Germany",
                            "FR" => "France",
                            "JP" => "Japan",
                            "CN" => "China",
                            _ => profile.Country
                        };
                        descriptionAttrs["Country"] = countryName;
                    }

                    // Rebuild description
                    var newDescParts = new List<string>();

                    if (descriptionAttrs.TryGetValue("Department", out var dept))
                        newDescParts.Add($"Department: {dept}");

                    if (descriptionAttrs.TryGetValue("Account Status", out var status))
                        newDescParts.Add($"Account Status: {status}");

                    foreach (var kvp in descriptionAttrs.OrderBy(k => k.Key))
                    {
                        if (kvp.Key.Equals("Department", StringComparison.OrdinalIgnoreCase) ||
                            kvp.Key.Equals("Account Status", StringComparison.OrdinalIgnoreCase))
                            continue;

                        newDescParts.Add($"{kvp.Key}: {kvp.Value}");
                    }

                    if (newDescParts.Any())
                    {
                        var descMod = new DirectoryAttributeModification
                        {
                            Name = "description",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        descMod.Add(string.Join("; ", newDescParts));
                        modifications.Add(descMod);
                    }
                }
                else
                {
                    // AD - direct attribute updates
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

                    if (!string.IsNullOrWhiteSpace(profile.DisplayName))
                    {
                        ReplaceIfProvided("displayName", profile.DisplayName);
                    }

                    ReplaceIfProvided(_attributeMapper.MapAttribute("Phone"), profile.TelephoneNumber);
                    ReplaceIfProvided("streetAddress", profile.StreetAddress);
                    ReplaceIfProvided("l", profile.City);
                    ReplaceIfProvided("st", profile.State);
                    ReplaceIfProvided("postalCode", profile.PostalCode);
                    ReplaceIfProvided("c", profile.Country);
                }

                if (modifications.Any())
                {
                    var modifyRequest = new ModifyRequest(userDn, modifications.ToArray());
                    connection.SendRequest(modifyRequest);
                    Console.WriteLine($"Applied {modifications.Count} updates to {userDn}");
                }

                if (!string.IsNullOrWhiteSpace(profile.NewPassword))
                {
                    ChangePassword(connection, userDn, profile.NewPassword);
                }
            });
        }
        private void ChangePassword(LdapConnection connection, string userDn, string newPassword)
        {
            try
            {
                var username = ExtractUsernameFromDn(userDn);
                // Validate password against policy first
                ValidatePasswordPolicy(newPassword, username);

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

            string? managerDn = null;
            if (!string.IsNullOrWhiteSpace(newUser.ManagerEmail))
            {
                managerDn = FindUserDn(connection, newUser.ManagerEmail);
                if (managerDn == null)
                {
                    throw new InvalidOperationException($"Manager user '{newUser.ManagerEmail}' does not exist.");
                }
            }
            ;

            if (!string.IsNullOrWhiteSpace(newUser.Country) && newUser.Country.Length != 2)
            {
                throw new InvalidOperationException(
                    "Country must be a 2-letter ISO code (e.g., IN, US, GB)."
                );
            }

            // Generate username based on LDAP type
            string username;
            string userRdn; // RDN (Relative Distinguished Name)

            if (_attributeMapper.IsActiveDirectory)
            {
                username = GenerateSamAccountName(newUser.FullName);
                if (UserExistsBySamAccountName(connection, username))
                {
                    throw new InvalidOperationException($"User '{username}' already exists.");
                }

                var commonName = GenerateCommonName(newUser.FullName);
                userRdn = $"CN={EscapeDnValue(commonName)}";
            }
            else
            {
                username = GenerateUid(newUser.FullName);
                if (UserExistsByUid(connection, username))
                {
                    throw new InvalidOperationException($"User '{username}' already exists.");
                }
                userRdn = $"uid={EscapeDnValue(username)}";
            }

            var email = $"{username}@{_ldapSettings.EmailFormat}";
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
                attributes.Add(new DirectoryAttribute("userPrincipalName", $"{username}@{_ldapSettings.EmailFormat}"));
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
                    await Task.Delay(200);

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

                Console.WriteLine("Attributes that failed:");
                foreach (var attr in attributes)
                {
                    try
                    {
                        var values = attr.GetValues(typeof(string));
                        Console.WriteLine($"  {attr.Name}: {string.Join(", ", values.Cast<string>())}");
                    }
                    catch { }
                }

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
                        new DirectoryAttribute("userPrincipalName", $"{username}@{_ldapSettings.EmailFormat}"),
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
                        Email = $"{username}@{_ldapSettings.EmailFormat}",
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
                    Console.WriteLine($"Minimal OpenLDAP user created: {username}");

                    // Now try to add all additional attributes including address fields
                    await Task.Delay(100);

                    var additionalMods = new List<DirectoryAttributeModification>();

                    // Add department in description
                    if (!string.IsNullOrWhiteSpace(newUser.Department))
                    {
                        var descMod = new DirectoryAttributeModification
                        {
                            Name = "description",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        descMod.Add($"Department: {newUser.Department}");
                        additionalMods.Add(descMod);
                    }

                    // Title
                    if (!string.IsNullOrWhiteSpace(newUser.Title))
                    {
                        var mod = new DirectoryAttributeModification
                        {
                            Name = "title",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        mod.Add(newUser.Title);
                        additionalMods.Add(mod);
                    }

                    // Telephone
                    if (!string.IsNullOrWhiteSpace(newUser.TelephoneNumber))
                    {
                        var mod = new DirectoryAttributeModification
                        {
                            Name = "telephoneNumber",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        mod.Add(newUser.TelephoneNumber);
                        additionalMods.Add(mod);
                    }

                    // Manager
                    if (managerDn != null)
                    {
                        var mod = new DirectoryAttributeModification
                        {
                            Name = "manager",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        mod.Add(managerDn);
                        additionalMods.Add(mod);
                    }

                    // ✅ ADDRESS FIELDS - Try to add them one by one
                    if (!string.IsNullOrWhiteSpace(newUser.StreetAddress))
                    {
                        try
                        {
                            var mod = new DirectoryAttributeModification
                            {
                                Name = "streetAddress",
                                Operation = DirectoryAttributeOperation.Add
                            };
                            mod.Add(newUser.StreetAddress);
                            additionalMods.Add(mod);
                            Console.WriteLine("Added streetAddress");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine($"Could not add streetAddress: {exc.Message}");
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(newUser.City))
                    {
                        try
                        {
                            var mod = new DirectoryAttributeModification
                            {
                                Name = "l", // locality
                                Operation = DirectoryAttributeOperation.Add
                            };
                            mod.Add(newUser.City);
                            additionalMods.Add(mod);
                            Console.WriteLine("Added city (l)");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine($"Could not add city: {exc.Message}");
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(newUser.State))
                    {
                        try
                        {
                            var mod = new DirectoryAttributeModification
                            {
                                Name = "st",
                                Operation = DirectoryAttributeOperation.Add
                            };
                            mod.Add(newUser.State);
                            additionalMods.Add(mod);
                            Console.WriteLine("Added state (st)");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine($"Could not add state: {exc.Message}");
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(newUser.PostalCode))
                    {
                        try
                        {
                            var mod = new DirectoryAttributeModification
                            {
                                Name = "postalCode",
                                Operation = DirectoryAttributeOperation.Add
                            };
                            mod.Add(newUser.PostalCode);
                            additionalMods.Add(mod);
                            Console.WriteLine("Added postalCode");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine($"Could not add postalCode: {exc.Message}");
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(newUser.Country))
                    {
                        try
                        {
                            // First, check if we need to add the country object class
                            var checkCountryClass = new SearchRequest(
                                userDn,
                                "(objectClass=*)",
                                SearchScope.Base,
                                "objectClass"
                            );

                            var checkResponse = (SearchResponse)connection.SendRequest(checkCountryClass);
                            var entry = checkResponse.Entries.Cast<SearchResultEntry>().FirstOrDefault();

                            bool countryClassAdded = false;

                            if (entry != null)
                            {
                                var objectClasses = entry.Attributes["objectClass"]
                                    .GetValues(typeof(string))
                                    .Cast<string>()
                                    .ToList();

                                // Add country object class if not present
                                if (!objectClasses.Contains("country", StringComparer.OrdinalIgnoreCase) &&
                                    !objectClasses.Contains("c", StringComparer.OrdinalIgnoreCase))
                                {
                                    var addCountryClass = new DirectoryAttributeModification
                                    {
                                        Name = "objectClass",
                                        Operation = DirectoryAttributeOperation.Add
                                    };
                                    addCountryClass.Add("country");

                                    // Send as separate modify request
                                    var classRequest = new ModifyRequest(userDn, addCountryClass);
                                    connection.SendRequest(classRequest);
                                    Console.WriteLine("Added country object class");
                                    countryClassAdded = true;

                                    // Important: Wait for LDAP to process the schema change
                                    await Task.Delay(500);
                                }
                            }

                            // Now add the country attribute in a SEPARATE request
                            try
                            {
                                var countryMod = new DirectoryAttributeModification
                                {
                                    Name = "c",
                                    Operation = DirectoryAttributeOperation.Add
                                };
                                countryMod.Add(newUser.Country.ToUpper());

                                var countryRequest = new ModifyRequest(userDn, countryMod);
                                connection.SendRequest(countryRequest);
                                Console.WriteLine($"Added country (c): {newUser.Country.ToUpper()}");

                                // Also add to additionalMods for tracking, but we already sent it
                                var mod = new DirectoryAttributeModification
                                {
                                    Name = "c",
                                    Operation = DirectoryAttributeOperation.Add
                                };
                                mod.Add(newUser.Country.ToUpper());
                                additionalMods.Add(mod); // Just for tracking
                            }
                            catch (Exception exc)
                            {
                                Console.WriteLine($"Could not add country attribute 'c': {exc.Message}");

                                // If 'c' fails, try 'co' as before
                                try
                                {
                                    var mod = new DirectoryAttributeModification
                                    {
                                        Name = "co",
                                        Operation = DirectoryAttributeOperation.Add
                                    };

                                    string countryName = newUser.Country.ToUpper() switch
                                    {
                                        "IN" => "India",
                                        "US" => "United States",
                                        "UK" => "United Kingdom",
                                        "CA" => "Canada",
                                        "AU" => "Australia",
                                        "DE" => "Germany",
                                        "FR" => "France",
                                        "JP" => "Japan",
                                        "CN" => "China",
                                        _ => newUser.Country
                                    };

                                    mod.Add(countryName);

                                    // Send 'co' in a separate request too
                                    var coRequest = new ModifyRequest(userDn, mod);
                                    connection.SendRequest(coRequest);
                                    additionalMods.Add(mod);
                                    Console.WriteLine($"Added country as friendly name (co): {countryName}");
                                }
                                catch (Exception exc2)
                                {
                                    Console.WriteLine($"Could not add country as friendly name: {exc2.Message}");

                                    // Last resort: Add to description
                                    try
                                    {
                                        var descMod = additionalMods.FirstOrDefault(m => m.Name == "description");
                                        if (descMod != null)
                                        {
                                            var currentDesc = descMod.GetValues(typeof(string))?.FirstOrDefault()?.ToString() ?? "";
                                            descMod.Clear();
                                            descMod.Add($"{currentDesc}; Country: {newUser.Country}");
                                        }
                                        else
                                        {
                                            descMod = new DirectoryAttributeModification
                                            {
                                                Name = "description",
                                                Operation = DirectoryAttributeOperation.Replace
                                            };
                                            descMod.Add($"Department: {newUser.Department}; Country: {newUser.Country}");
                                            additionalMods.Add(descMod);
                                        }
                                        Console.WriteLine("Added country to description as fallback");
                                    }
                                    catch (Exception exc3)
                                    {
                                        Console.WriteLine($"Could not add country anywhere: {exc3.Message}");
                                    }
                                }
                            }
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine($"Error in country handling: {exc.Message}");
                        }
                    }

                    // Apply all modifications
                    if (additionalMods.Any())
                    {
                        try
                        {
                            var modifyRequest = new ModifyRequest(userDn, additionalMods.ToArray());
                            connection.SendRequest(modifyRequest);
                            Console.WriteLine($"Added {additionalMods.Count} additional attributes to user");
                        }
                        catch (Exception exc)
                        {
                            Console.WriteLine($"Warning: Could not add all attributes: {exc.Message}");
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
                // AD: First check if the department OU exists under Employees
                var escapedDepartment = EscapeOuName(department);
                var standardPath = $"OU={escapedDepartment},OU=Employees,{_ldapSettings.BaseDn}";

                if (DepartmentOuExists(connection, standardPath))
                {
                    Console.WriteLine($"Found AD department at: {standardPath}");
                    return standardPath;
                }

                // If not, check if it exists directly under base
                var directPath = $"OU={Escape(department)},{_ldapSettings.BaseDn}";
                if (DepartmentOuExists(connection, directPath))
                {
                    Console.WriteLine($"Found AD department at: {directPath}");
                    return directPath;
                }

                // If department OU doesn't exist, throw helpful error
                throw new InvalidOperationException(
                    $"Department OU '{department}' not found in AD. " +
                    $"Checked locations: {standardPath}, {directPath}. " +
                    $"Please create the OU first or use an existing department.");
            }
            else
            {
                // OpenLDAP: Standard structure (lowercase for OpenLDAP)
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
        private static string EscapeDnValue(string value)
        {
            if (string.IsNullOrEmpty(value)) return value;

            // Escape characters that need escaping in DN values
            var sb = new StringBuilder();
            foreach (char c in value)
            {
                switch (c)
                {
                    case ',':
                        sb.Append("\\,");
                        break;
                    case '\\':
                        sb.Append("\\\\");
                        break;
                    case '#':
                        sb.Append("\\#");
                        break;
                    case '+':
                        sb.Append("\\+");
                        break;
                    case '"':
                        sb.Append("\\\"");
                        break;
                    case '<':
                        sb.Append("\\<");
                        break;
                    case '>':
                        sb.Append("\\>");
                        break;
                    case ';':
                        sb.Append("\\;");
                        break;
                    default:
                        sb.Append(c);
                        break;
                }
            }
            return sb.ToString();

        }

        private bool UserExistsBySamAccountName(LdapConnection connection, string samAccountName)
        {
            try
            {
                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(sAMAccountName={Escape(samAccountName)})",
                    SearchScope.Subtree,
                    "sAMAccountName"
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
            // For OpenLDAP: similar format but ensure it works for both
            var nameParts = fullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (nameParts.Length < 2)
            {
                return fullName.ToLowerInvariant();
            }

            var firstName = nameParts[0].ToLowerInvariant();
            var lastName = nameParts[^1].ToLowerInvariant();
            var baseUid = $"{firstName}.{lastName}";

            baseUid = System.Text.RegularExpressions.Regex.Replace(baseUid, @"[^a-z0-9.]", "");

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

            // Build rich description with all available information
            var descParts = new List<string>();

            if (!string.IsNullOrWhiteSpace(newUser.Department))
                descParts.Add($"Department: {newUser.Department}");

            descParts.Add("Account Status: Active"); //default

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

            // Add ALL address fields to description
            if (!string.IsNullOrWhiteSpace(newUser.StreetAddress))
                descParts.Add($"Street: {newUser.StreetAddress}");

            if (!string.IsNullOrWhiteSpace(newUser.City))
                descParts.Add($"City: {newUser.City}");

            if (!string.IsNullOrWhiteSpace(newUser.State))
                descParts.Add($"State: {newUser.State}");

            if (!string.IsNullOrWhiteSpace(newUser.PostalCode))
                descParts.Add($"PostalCode: {newUser.PostalCode}");

            if (!string.IsNullOrWhiteSpace(newUser.Country))
            {
                // Convert country code to full name for readability
                string countryName = newUser.Country.ToUpper() switch
                {
                    "IN" => "India",
                    "US" => "United States",
                    "UK" => "United Kingdom",
                    "CA" => "Canada",
                    "AU" => "Australia",
                    "DE" => "Germany",
                    "FR" => "France",
                    "JP" => "Japan",
                    "CN" => "China",
                    _ => newUser.Country
                };
                descParts.Add($"Country: {countryName}");
            }

            // Update description with all parts
            if (descParts.Any())
            {
                var descMod = new DirectoryAttributeModification
                {
                    Name = "description",
                    Operation = DirectoryAttributeOperation.Replace
                };
                descMod.Add(string.Join("; ", descParts));
                modifications.Add(descMod);
                Console.WriteLine($"Updated description with: {string.Join("; ", descParts)}");
            }

            if (modifications.Count > 0)
            {
                var modifyRequest = new ModifyRequest(userDn, modifications.ToArray());
                connection.SendRequest(modifyRequest);
                Console.WriteLine($"Applied {modifications.Count} attribute updates");
            }
        }
        private bool ValidatePasswordPolicy(string password, string? username = null)
        {
            var validationResult = _passwordPolicyValidator.ValidatePassword(password, username);

            if (!validationResult.IsValid)
            {
                var errors = string.Join("; ", validationResult.Errors);
                throw new InvalidOperationException($"Password validation failed: {errors}");
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
        private string EscapeOuName(string ouName)
        {
            if (string.IsNullOrEmpty(ouName)) return ouName;

            // Escape special characters in OU names
            return ouName
                .Replace("\\", "\\\\")
                .Replace(",", "\\,")
                .Replace("#", "\\#")
                .Replace("+", "\\+")
                .Replace("\"", "\\\"")
                .Replace("<", "\\<")
                .Replace(">", "\\>")
                .Replace(";", "\\;")
                .Replace("=", "\\=");
        }

        private string GenerateCommonName(string fullName)
        {
            // CN should be the full name without dots, just spaces
            // For "Parth Sharma", CN should be "Parth Sharma" not "parth.sharma"
            return fullName.Trim();
        }
        public string GenerateSamAccountName(string fullName)
        {
            // Generate base username with dots for sAMAccountName: "parth.sharma"
            var nameParts = fullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (nameParts.Length < 2)
            {
                // Single name - just lowercase it
                return fullName.ToLowerInvariant();
            }

            // Format: firstname.lastname (lowercase) for sAMAccountName
            var firstName = nameParts[0].ToLowerInvariant();
            var lastName = nameParts[^1].ToLowerInvariant();
            var baseName = $"{firstName}.{lastName}";

            // Clean up special characters (keep dots for sAMAccountName)
            baseName = System.Text.RegularExpressions.Regex.Replace(baseName, @"[^a-z0-9.]", "");

            var samAccountName = baseName;
            int suffix = 1;

            // Check if username exists
            using (var connection = _ldapAuthenticator.BindAsServiceAccount())
            {
                while (true)
                {
                    var existingUser = GetByUsernameAsync(connection, samAccountName).Result;
                    if (existingUser == null)
                    {
                        return samAccountName;
                    }
                    samAccountName = $"{baseName}{suffix}";
                    suffix++;
                }
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
                        try
                        {
                            // Find target OU for the new department
                            var targetOuDn = GetDepartmentOuDnForMove(connection, command.Department);

                            // Check if we're already in the target OU
                            var currentParentDn = GetParentOuDn(userDn);

                            if (!string.Equals(currentParentDn, targetOuDn, StringComparison.OrdinalIgnoreCase))
                            {
                                // Extract the RDN (CN=...) from current DN
                                var rdn = GetRdnFromDn(userDn);

                                // Move user to new OU
                                ADMoveUserToOu(connection, userDn, targetOuDn);

                                // Update DN after move
                                newUserDn = $"{rdn},{targetOuDn}";

                                Console.WriteLine($"AD: Moved user from '{currentParentDn}' to '{targetOuDn}'");
                            }
                            else
                            {
                                Console.WriteLine($"AD: User already in department OU '{targetOuDn}'");
                            }

                            // Update department attribute regardless of move
                            var deptMod = new DirectoryAttributeModification
                            {
                                Name = "department",
                                Operation = DirectoryAttributeOperation.Replace
                            };
                            deptMod.Add(command.Department);
                            modifications.Add(deptMod);

                            Console.WriteLine($"AD: Updated department attribute to '{command.Department}'");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Warning: Could not move user to department OU: {ex.Message}");

                            // Still update department attribute even if move fails
                            var deptMod = new DirectoryAttributeModification
                            {
                                Name = "department",
                                Operation = DirectoryAttributeOperation.Replace
                            };
                            deptMod.Add(command.Department);
                            modifications.Add(deptMod);
                        }
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
        // Helper method to get RDN from DN
        private static string GetRdnFromDn(string dn)
        {
            if (string.IsNullOrEmpty(dn))
                return string.Empty;

            var parts = dn.Split(',', 2);
            return parts.Length > 0 ? parts[0] : dn;
        }

        // Helper method to find department OU for moving users
        private string GetDepartmentOuDnForMove(LdapConnection connection, string department)
        {
            if (string.IsNullOrWhiteSpace(department))
                throw new ArgumentException("Department name cannot be empty");

            Console.WriteLine($"Looking for department OU for move: '{department}'");

            if (_attributeMapper.IsActiveDirectory)
            {
                // AD: Try different possible OU structures
                var possiblePaths = new[]
                {
            $"OU={Escape(department)},OU=Employees,{_ldapSettings.BaseDn}",
            $"OU={Escape(department)},{_ldapSettings.BaseDn}",
            $"CN={Escape(department)},OU=Employees,{_ldapSettings.BaseDn}",
            $"CN={Escape(department)},{_ldapSettings.BaseDn}"
            };

                foreach (var path in possiblePaths)
                {
                    try
                    {
                        if (DepartmentOuExists(connection, path))
                        {
                            Console.WriteLine($"Found department OU for move at: {path}");
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
                    $"Department OU '{department}' not found for move. " +
                    $"Tried locations: {string.Join(", ", possiblePaths)}");
            }
            else
            {
                // OpenLDAP: Use existing method
                return GetDepartmentOuDnAsync(connection, department);
            }
        }

        // Improved MoveUserToOu method
        private void ADMoveUserToOu(LdapConnection connection, string userDn, string targetOuDn)
        {
            var currentParentDn = GetParentOuDn(userDn);

            // If already in target OU → do nothing
            if (string.Equals(currentParentDn, targetOuDn, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine($"User already in target OU: {targetOuDn}");
                return;
            }

            // Extract RDN
            var rdn = GetRdnFromDn(userDn);

            Console.WriteLine($"Moving user: RDN={rdn}, From={currentParentDn}, To={targetOuDn}");

            try
            {
                var request = new ModifyDNRequest(userDn, targetOuDn, rdn)
                {
                    DeleteOldRdn = true
                };

                connection.SendRequest(request);
                Console.WriteLine($"Successfully moved user to {targetOuDn}");
            }
            catch (DirectoryOperationException ex)
            {
                Console.WriteLine($"Move failed: {ex.Message} (Error code: {ex.Response?.ResultCode})");

                // Check for common errors
                if (ex.Response?.ErrorMessage?.Contains("object class violation") == true)
                {
                    throw new InvalidOperationException(
                        $"Cannot move user to '{targetOuDn}'. " +
                        $"The target OU might have restrictions or the user object class is not allowed there.");
                }

                throw new InvalidOperationException($"Failed to move user: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error during move: {ex.Message}");
                throw new InvalidOperationException($"Failed to move user: {ex.Message}", ex);
            }
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
        private static string GetParentOuDn(string dn)
        {
            if (string.IsNullOrEmpty(dn))
                throw new InvalidOperationException("Invalid DN: cannot be null or empty");

            var parts = dn.Split(',');
            if (parts.Length < 2)
                throw new InvalidOperationException($"Invalid DN format: {dn}");

            // Rejoin everything except the first part (RDN)
            return string.Join(",", parts, 1, parts.Length - 1);
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


        public async Task DeleteUserAsync(string distinguishedName)
        {
            if (string.IsNullOrWhiteSpace(distinguishedName))
                throw new ArgumentException("Distinguished name cannot be empty.", nameof(distinguishedName));

            await Task.Run(() =>
            {
                // Use write service account — same connection type used by
                // CreateUserAsync, UpdateUserStatusAsync, UpdateUserAsAdminAsync
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

                try
                {
                    var deleteRequest = new DeleteRequest(distinguishedName);
                    connection.SendRequest(deleteRequest);

                    Console.WriteLine($"[LdapUserRepository] DeleteUserAsync: removed {distinguishedName}");
                }
                catch (DirectoryOperationException ex)
                {
                    // Log the specific LDAP error code for diagnostics
                    Console.WriteLine(
                        $"[LdapUserRepository] DeleteUserAsync failed for {distinguishedName}. " +
                        $"LDAP error: {ex.Message}. " +
                        $"Response code: {ex.Response?.ResultCode}");
                    throw new InvalidOperationException(
                        $"Failed to delete LDAP user '{distinguishedName}': {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Reads pwdAccountLockedTime from OpenLDAP ppolicy to determine
        /// if the account is locked and how long the lockout lasts.
        ///
        /// CALLED BY: AuthenticationService.LoginDetailedAsync()
        ///            AuthenticationService.GetLockoutStatusAsync()
        ///
        /// DOES NOT take a LdapConnection parameter because lockout checks
        /// need to happen independently of the user BIND flow — we need
        /// to check lockout status BEFORE attempting a BIND (to avoid
        /// incrementing the failure counter on an already locked account)
        /// and AFTER a failed BIND (to report fresh lockout info).
        ///
        /// Uses its own service account connection internally.
        ///
        /// OpenLDAP ppolicy lockout format:
        ///   pwdAccountLockedTime = "yyyyMMddHHmmssZ" (generalized time)
        ///   "000001010000Z" = permanently locked (epoch zero)
        ///   Absent or empty = not locked
        ///
        /// Your ppolicy settings (from our earlier work):
        ///   pwdMaxFailure: 3
        ///   pwdLockoutDuration: 600 (seconds)
        /// </summary>
        public Task<(bool IsLocked, int? RemainingSeconds)> ReadLockoutStatusAsync(
            string userDn)
        {
            // Use Task.Run with explicit return type to avoid CS8030.
            // The compiler cannot infer the tuple return type from an
            // anonymous lambda inside Task.Run — the explicit generic
            // parameter fixes this.
            return Task.Run<(bool IsLocked, int? RemainingSeconds)>(() =>
            {
                try
                {
                    using var connection = _ldapAuthenticator.BindAsServiceAccount();

                    var searchRequest = new SearchRequest(
                        userDn,
                        "(objectClass=*)",
                        SearchScope.Base,
                        "pwdAccountLockedTime",
                        "pwdFailureTime"
                    );

                    var response = (SearchResponse)connection.SendRequest(searchRequest);
                    var entry = response.Entries
                        .Cast<SearchResultEntry>()
                        .FirstOrDefault();

                    if (entry == null)
                        return (false, null);

                    if (!entry.Attributes.Contains("pwdAccountLockedTime"))
                        return (false, null);

                    var lockedTimeStr = entry.Attributes["pwdAccountLockedTime"][0]
                        ?.ToString();

                    if (string.IsNullOrEmpty(lockedTimeStr))
                        return (false, null);

                    // "000001010000Z" = permanently locked (OpenLDAP convention)
                    if (lockedTimeStr == "000001010000Z")
                        return (true, -1);

                    // Parse generalized time: yyyyMMddHHmmssZ
                    if (DateTime.TryParseExact(
                            lockedTimeStr,
                            "yyyyMMddHHmmssZ",
                            System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.AssumeUniversal |
                            System.Globalization.DateTimeStyles.AdjustToUniversal,
                            out var lockedAt))
                    {
                        // pwdLockoutDuration = 600 seconds (your ppolicy config)
                        const int LockoutDurationSeconds = 600;

                        var unlockAt = lockedAt.AddSeconds(LockoutDurationSeconds);
                        var remaining = (int)(unlockAt - DateTime.UtcNow).TotalSeconds;

                        if (remaining > 0)
                            return (true, remaining);

                        // Lockout window has passed — account is usable again
                        return (false, null);
                    }

                    // Could not parse the timestamp — treat conservatively as locked
                    Console.WriteLine(
                        $"[ReadLockoutStatus] Could not parse pwdAccountLockedTime " +
                        $"'{lockedTimeStr}' for {userDn}. Treating as locked.");
                    return (true, -1);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        $"[ReadLockoutStatus] Error reading ppolicy for {userDn}: " +
                        $"{ex.Message}");

                    // Fail open — if we cannot read lockout status, do not
                    // block the user. The BIND attempt will surface the real error.
                    return (false, null);
                }
            }
            );
        }


        /// <summary>
        /// Creates a consumer user in OpenLDAP with all fields from
        /// CreateConsumerCommand, then returns a CreateConsumerResult
        /// containing the generated username, email, password, DN,
        /// and name parts.
        ///
        /// DIFFERENCE from CreateUserAsync:
        ///   CreateUserAsync takes CreateUserCommand (legacy, fewer fields).
        ///   CreateConsumerAsync takes CreateConsumerCommand (full fields
        ///   including gender, emptype, branch etc. — these are NOT stored
        ///   in LDAP but are returned in the result so DirectoryService can
        ///   pass them to Oidc.Server for PostgreSQL insertion).
        ///   
        /// </summary>
        public async Task<CreateConsumerResult> CreateConsumerAsync(
            CreateConsumerCommand command)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

            // ── Validate department OU exists ─────────────────────────
            string departmentOuDn;
            try
            {
                departmentOuDn = DetermineDepartmentOuDn(connection, command.Department);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Failed to find department OU: {ex.Message}");
            }

            // ── Resolve manager DN if provided ────────────────────────
            string? managerDn = null;
            if (!string.IsNullOrWhiteSpace(command.ManagerEmail))
            {
                managerDn = FindUserDn(connection, command.ManagerEmail);
                if (managerDn == null) throw new InvalidOperationException($"Manager '{command.ManagerEmail}' does not exist.");
            }

            // ── Validate country format ───────────────────────────────
            if (!string.IsNullOrWhiteSpace(command.Country) && command.Country.Length != 2)
                throw new InvalidOperationException("Country must be a 2-letter ISO code (e.g., IN, US, GB).");

            // ── Generate uid / username ───────────────────────────────
            string username;
            string userRdn;

            if (_attributeMapper.IsActiveDirectory)
            {
                username = GenerateSamAccountName(command.FullName);
                if (UserExistsBySamAccountName(connection, username))
                {
                    throw new InvalidOperationException($"User '{username}' already exists.");
                }

                var commonName = GenerateCommonName(command.FullName);
                userRdn = $"CN={EscapeDnValue(commonName)}";
            }
            else
            {
                username = GenerateUid(command.FullName);
                if (UserExistsByUid(connection, username))
                {
                    throw new InvalidOperationException($"User '{username}' already exists.");
                }
                userRdn = $"uid={EscapeDnValue(username)}";
            }

            // ── Derive values ─────────────────────────────────────────
            var email = $"{username}@{_ldapSettings.EmailFormat}";
            var userDn = $"{userRdn},{departmentOuDn}";
            var password = GenerateStrongPassword();
            var nameParts = command.FullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var firstName = nameParts.Length > 0 ? nameParts[0] : "";
            var lastName = nameParts.Length > 1 ? nameParts[^1] : firstName;

            // ── Prevent self-management ───────────────────────────────
            if (managerDn != null && managerDn.Equals(userDn, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("A user cannot be their own manager.");

            // ── Build LDAP attributes ─────────────────────────────────
            var attributes = new List<DirectoryAttribute>();

            if (_attributeMapper.IsActiveDirectory)
            {
                attributes.Add(new DirectoryAttribute("objectClass",
                    new[] { "top", "person", "organizationalPerson", "user" }));
                attributes.Add(new DirectoryAttribute("cn", command.FullName));
                attributes.Add(new DirectoryAttribute("name", command.FullName));
                attributes.Add(new DirectoryAttribute("givenName", firstName));
                attributes.Add(new DirectoryAttribute("sn", lastName));
                attributes.Add(new DirectoryAttribute("sAMAccountName", username));
                attributes.Add(new DirectoryAttribute("userPrincipalName",
                    $"{username}@{_ldapSettings.EmailFormat}"));
                attributes.Add(new DirectoryAttribute("mail", email));
                attributes.Add(new DirectoryAttribute("displayName", command.FullName));
                attributes.Add(new DirectoryAttribute("userAccountControl", "514"));

                if (!string.IsNullOrWhiteSpace(command.Department))
                    attributes.Add(new DirectoryAttribute("department", command.Department));
                if (!string.IsNullOrWhiteSpace(command.Title))
                    attributes.Add(new DirectoryAttribute("title", command.Title));
                if (!string.IsNullOrWhiteSpace(command.TelephoneNumber))
                    attributes.Add(new DirectoryAttribute("telephoneNumber",
                        command.TelephoneNumber));
                if (managerDn != null)
                    attributes.Add(new DirectoryAttribute("manager", managerDn));
                if (!string.IsNullOrWhiteSpace(command.StreetAddress))
                    attributes.Add(new DirectoryAttribute("streetAddress",
                        command.StreetAddress));
                if (!string.IsNullOrWhiteSpace(command.City))
                    attributes.Add(new DirectoryAttribute("l", command.City));
                if (!string.IsNullOrWhiteSpace(command.State))
                    attributes.Add(new DirectoryAttribute("st", command.State));
                if (!string.IsNullOrWhiteSpace(command.PostalCode))
                    attributes.Add(new DirectoryAttribute("postalCode", command.PostalCode));
                if (!string.IsNullOrWhiteSpace(command.Country))
                    attributes.Add(new DirectoryAttribute("c",
                        command.Country.ToUpper()));
            }
            else
            {
                // ── OpenLDAP ──────────────────────────────────────────
                attributes.Add(new DirectoryAttribute("objectClass",
                    new[] { "top", "person", "organizationalPerson", "inetOrgPerson" }));
                attributes.Add(new DirectoryAttribute("cn", command.FullName));
                attributes.Add(new DirectoryAttribute("givenName", firstName));
                attributes.Add(new DirectoryAttribute("sn", lastName));
                attributes.Add(new DirectoryAttribute("uid", username));
                attributes.Add(new DirectoryAttribute("userPassword",
                    GenerateSSHAHash(password)));
                attributes.Add(new DirectoryAttribute("mail", email));

                // Build rich description string for OpenLDAP
                // (department, status, address fields all live here)
                var descParts = new List<string>();
                if (!string.IsNullOrWhiteSpace(command.Department))
                    descParts.Add($"Department: {command.Department}");
                descParts.Add("Account Status: Active");
                if (!string.IsNullOrWhiteSpace(command.StreetAddress))
                    descParts.Add($"Street: {command.StreetAddress}");
                if (!string.IsNullOrWhiteSpace(command.City))
                    descParts.Add($"City: {command.City}");
                if (!string.IsNullOrWhiteSpace(command.State))
                    descParts.Add($"State: {command.State}");
                if (!string.IsNullOrWhiteSpace(command.PostalCode))
                    descParts.Add($"PostalCode: {command.PostalCode}");
                if (!string.IsNullOrWhiteSpace(command.Country))
                {
                    string countryName = command.Country.ToUpper() switch
                    {
                        "IN" => "India",
                        "US" => "United States",
                        "UK" => "United Kingdom",
                        "CA" => "Canada",
                        "AU" => "Australia",
                        "DE" => "Germany",
                        "FR" => "France",
                        "JP" => "Japan",
                        "CN" => "China",
                        _ => command.Country
                    };
                    descParts.Add($"Country: {countryName}");
                }

                attributes.Add(new DirectoryAttribute("description",
                    string.Join("; ", descParts)));

                if (!string.IsNullOrWhiteSpace(command.Title))
                    attributes.Add(new DirectoryAttribute("title", command.Title));
                if (!string.IsNullOrWhiteSpace(command.TelephoneNumber))
                    attributes.Add(new DirectoryAttribute("telephoneNumber",
                        command.TelephoneNumber));
                if (managerDn != null)
                    attributes.Add(new DirectoryAttribute("manager", managerDn));
                if (!string.IsNullOrWhiteSpace(command.StreetAddress))
                    attributes.Add(new DirectoryAttribute("streetAddress",
                        command.StreetAddress));
                if (!string.IsNullOrWhiteSpace(command.City))
                    attributes.Add(new DirectoryAttribute("l", command.City));
                if (!string.IsNullOrWhiteSpace(command.State))
                    attributes.Add(new DirectoryAttribute("st", command.State));
                if (!string.IsNullOrWhiteSpace(command.PostalCode))
                    attributes.Add(new DirectoryAttribute("postalCode",
                        command.PostalCode));
            }

            // ── Send AddRequest ───────────────────────────────────────
            var addRequest = new AddRequest(userDn, attributes.ToArray());
            connection.SendRequest(addRequest);
            Console.WriteLine($"[CreateConsumerAsync] LDAP user created: {userDn}");

            // ── AD: set password + enable ─────────────────────────────
            if (_attributeMapper.IsActiveDirectory)
            {
                await Task.Delay(200);
                try
                {
                    ChangePasswordAD(connection, userDn, password);
                    var enableMod = new DirectoryAttributeModification
                    {
                        Name = "userAccountControl",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    enableMod.Add("512");
                    connection.SendRequest(new ModifyRequest(userDn, enableMod));
                }
                catch (Exception ex)
                {
                    Console.WriteLine(
                        $"[CreateConsumerAsync] Warning: AD password/enable failed: {ex.Message}");
                }
            }

            return new CreateConsumerResult
            {
                Username = username,
                Email = email,
                InitialPassword = password,
                DistinguishedName = userDn,
                FirstName = firstName,
                LastName = lastName
            };
        }

        /// <summary>
        /// Updates a consumer user in LDAP Server.
        /// Only non-null fields are updated.
        /// If Department changes → moves user to the new OU.
        /// If ManagerEmail changes → updates manager DN.
        /// 
        /// Does NOT touch PostgreSQL — that is handled by
        /// DirectoryService via Oidc.Server internal endpoint.
        /// </summary>
        public async Task UpdateConsumerAsync(UpdateConsumerCommand command)
        {
            await Task.Run(() =>
            {
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

                // ── Resolve user DN ───────────────────────────────────
                var user = GetByUsernameAsync(connection, command.Username).Result;
                if (user == null)
                    throw new InvalidOperationException($"User '{command.Username}' not found in LDAP.");

                var userDn = user.DistinguishedName;
                var modifications = new List<DirectoryAttributeModification>();

                // ── Department change → OU move ───────────────────────
                string? newUserDn = null;
                if (!string.IsNullOrWhiteSpace(command.Department))
                {
                    try
                    {
                        var targetOuDn = GetDepartmentOuDnAsync(connection, command.Department);
                        var currentParent = GetParentOuDn(userDn);

                        if (!string.Equals(currentParent, targetOuDn,StringComparison.OrdinalIgnoreCase))
                        {
                            MoveUserToOu(connection, userDn, targetOuDn);
                            var uid = ExtractUidFromDn(userDn);
                            newUserDn = $"uid={uid},{targetOuDn}";
                            Console.WriteLine($"[UpdateConsumerAsync] Moved to OU: {targetOuDn}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[UpdateConsumerAsync] OU move failed: {ex.Message}");
                    }
                }

                var effectiveUserDn = newUserDn ?? userDn;

                // ── Build LDAP modifications ──────────────────────────
                void AddReplace(string attr, string? value)
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

                if (_attributeMapper.IsActiveDirectory)
                {
                    AddReplace("displayName", command.DisplayName);
                    AddReplace("mail", command.Email);
                    AddReplace("title", command.Title);
                    AddReplace("telephoneNumber", command.TelephoneNumber);
                    AddReplace("streetAddress", command.StreetAddress);
                    AddReplace("l", command.City);
                    AddReplace("st", command.State);
                    AddReplace("postalCode", command.PostalCode);
                    if (!string.IsNullOrWhiteSpace(command.Country))
                        AddReplace("c", command.Country.ToUpper());
                    if (!string.IsNullOrWhiteSpace(command.Department))
                        AddReplace("department", command.Department);
                    if (!string.IsNullOrWhiteSpace(command.ManagerEmail))
                    {
                        var managerDn = FindUserDn(connection, command.ManagerEmail)
                            ?? throw new InvalidOperationException("Manager not found.");
                        AddReplace("manager", managerDn);
                    }
                }
                else
                {
                    // ── OpenLDAP: direct attributes ───────────────────
                    if (!string.IsNullOrWhiteSpace(command.DisplayName))
                        AddReplace("cn", command.DisplayName);
                    if (!string.IsNullOrWhiteSpace(command.Email))
                        AddReplace("mail", command.Email);
                    AddReplace("title", command.Title);
                    AddReplace("telephoneNumber", command.TelephoneNumber);

                    if (!string.IsNullOrWhiteSpace(command.ManagerEmail))
                    {
                        var managerDn = FindUserDn(connection, command.ManagerEmail)
                            ?? throw new InvalidOperationException("Manager not found.");
                        AddReplace("manager", managerDn);
                    }

                    // ── OpenLDAP: rebuild description string ──────────
                    // Fetch current description first so we preserve existing
                    // values for fields not being updated
                    var searchRequest = new SearchRequest(
                        effectiveUserDn,
                        "(objectClass=inetOrgPerson)",
                        SearchScope.Base,
                        "description");
                    var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                    var entry = searchResponse.Entries.Cast<SearchResultEntry>().FirstOrDefault();

                    string currentDesc = entry != null &&
                        entry.Attributes.Contains("description")
                        ? entry.Attributes["description"][0]?.ToString() ?? ""
                        : "";

                    var descAttrs = ParseDescriptionAttributes(currentDesc);

                    // Update only provided fields
                    if (!string.IsNullOrWhiteSpace(command.Department))
                        descAttrs["Department"] = command.Department;
                    if (!string.IsNullOrWhiteSpace(command.StreetAddress))
                        descAttrs["Street"] = command.StreetAddress;
                    if (!string.IsNullOrWhiteSpace(command.City))
                        descAttrs["City"] = command.City;
                    if (!string.IsNullOrWhiteSpace(command.State))
                        descAttrs["State"] = command.State;
                    if (!string.IsNullOrWhiteSpace(command.PostalCode))
                        descAttrs["PostalCode"] = command.PostalCode;
                    if (!string.IsNullOrWhiteSpace(command.Country))
                    {
                        string countryName = command.Country.ToUpper() switch
                        {
                            "IN" => "India",
                            "US" => "United States",
                            "UK" => "United Kingdom",
                            "CA" => "Canada",
                            "AU" => "Australia",
                            "DE" => "Germany",
                            "FR" => "France",
                            "JP" => "Japan",
                            "CN" => "China",
                            _ => command.Country
                        };
                        descAttrs["Country"] = countryName;
                    }

                    // Rebuild — always keep Department and Account Status first
                    var descParts = new List<string>();
                    if (descAttrs.TryGetValue("Department", out var dept))
                        descParts.Add($"Department: {dept}");
                    if (descAttrs.TryGetValue("Account Status", out var status))
                        descParts.Add($"Account Status: {status}");

                    foreach (var kvp in descAttrs.OrderBy(k => k.Key))
                    {
                        if (kvp.Key.Equals("Department",
                                StringComparison.OrdinalIgnoreCase) ||
                            kvp.Key.Equals("Account Status",
                                StringComparison.OrdinalIgnoreCase))
                            continue;
                        descParts.Add($"{kvp.Key}: {kvp.Value}");
                    }

                    if (descParts.Any())
                    {
                        var descMod = new DirectoryAttributeModification
                        {
                            Name = "description",
                            Operation = DirectoryAttributeOperation.Replace
                        };
                        descMod.Add(string.Join("; ", descParts));
                        modifications.Add(descMod);
                    }

                    // Street address as direct attribute too
                    AddReplace("streetAddress", command.StreetAddress);
                    AddReplace("l", command.City);
                    AddReplace("st", command.State);
                    AddReplace("postalCode", command.PostalCode);
                }

                // ── Apply modifications ───────────────────────────────
                if (modifications.Any())
                {
                    connection.SendRequest(
                        new ModifyRequest(effectiveUserDn, modifications.ToArray()));
                    Console.WriteLine(
                        $"[UpdateConsumerAsync] Applied {modifications.Count} " +
                        $"updates to {effectiveUserDn}");
                }
                else
                {
                    Console.WriteLine(
                        $"[UpdateConsumerAsync] No LDAP modifications for " +
                        $"{command.Username}");
                }
            });
        }

        /// <summary>
        /// Deletes a consumer user from OpenLDAP by username.
        ///
        /// Flow:
        ///   1. Bind as service account (write permissions)
        ///   2. Search for the user by uid to get their DN
        ///   3. Send a DeleteRequest using the resolved DN
        ///
        /// Why resolve DN here instead of accepting it as input?
        ///   The caller (DirectoryService / DirectoryController) only
        ///   knows the username — not the full DN. The DN depends on
        ///   which department OU the user lives in, and that is an
        ///   LDAP-internal concern. The repository knows how to find it.
        ///
        /// Throws:
        ///   InvalidOperationException → user not found in LDAP
        ///   InvalidOperationException → LDAP delete operation failed
        /// </summary>
        public async Task DeleteConsumerAsync(DeleteConsumerCommand command)
        {
            if (string.IsNullOrWhiteSpace(command.Username))
                throw new ArgumentException(
                    "Username cannot be empty.", nameof(command));

            await Task.Run(() =>
            {
                // ── Step 1: Bind as service account ───────────────────
                // Uses BindAsServiceAccountForWrite() — same account used
                // by CreateConsumerAsync, UpdateConsumerAsync etc.
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

                // ── Step 2: Resolve the user's DN by uid ──────────────
                // We search the entire tree because we don't know which
                // department OU the user is in.
                var searchRequest = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(uid={Escape(command.Username)})",
                    SearchScope.Subtree,
                    "distinguishedName"
                );

                var searchResponse =
                    (SearchResponse)connection.SendRequest(searchRequest);

                var entry = searchResponse.Entries
                    .Cast<SearchResultEntry>()
                    .FirstOrDefault();

                if (entry == null)
                {
                    throw new InvalidOperationException(
                        $"User '{command.Username}' not found in LDAP. " +
                        $"Cannot delete a user that does not exist.");
                }

                var userDn = entry.DistinguishedName;

                Console.WriteLine(
                    $"[DeleteConsumerAsync] Found user '{command.Username}' " +
                    $"at DN: {userDn}");

                // ── Step 3: Delete the LDAP entry ─────────────────────
                try
                {
                    var deleteRequest = new DeleteRequest(userDn);
                    connection.SendRequest(deleteRequest);

                    Console.WriteLine(
                        $"[DeleteConsumerAsync] Successfully deleted " +
                        $"'{command.Username}' from LDAP. DN: {userDn}");
                }
                catch (DirectoryOperationException ex)
                {
                    Console.WriteLine(
                        $"[DeleteConsumerAsync] LDAP delete failed for " +
                        $"'{command.Username}'. Error: {ex.Message}. " +
                        $"ResultCode: {ex.Response?.ResultCode}");

                    throw new InvalidOperationException(
                        $"Failed to delete user '{command.Username}' " +
                        $"from LDAP: {ex.Message}", ex);
                }
            });
        }
    }
}
