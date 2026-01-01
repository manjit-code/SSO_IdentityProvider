using Microsoft.Extensions.Options;
using SSO_IdentityProvider.Domain.Entities;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Infrastructure.Ldap
{
    public class LdapUserRepository : IUserRepository
    {
        private readonly LdapSettings _ldapSettings;
        public LdapUserRepository(IOptions<LdapSettings> option)
        {
            _ldapSettings = option.Value;
        }

        public async Task<User?> GetByUsernameAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() =>
            {

                var samAccountName = username.Contains("@")
                    ? username.Split('@')[0]
                    : username;
                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(sAMAccountName={samAccountName})",
                    SearchScope.Subtree,
                    "cn", "mail", "sAMAccountName"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                if (entry == null)
                {
                    return null;
                }

                var newUser = new User
                {
                    UserName = username,
                    DistinguishedName = entry.DistinguishedName
                };

                return newUser;
            });
        }

        public async Task<DirectoryUser?> GetMyProfileAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() =>
            {
                var sam = username.Contains("@")
                    ? username.Split('@')[0]
                    : username;

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(sAMAccountName={sam})",
                    SearchScope.Subtree,
                    "distinguishedName",
                    "displayName",
                    "mail",
                    "telephoneNumber",
                    "department",
                    "title",
                    "memberOf"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();

                if (entry == null) return null;

                var groups = new List<string>();
                if (entry.Attributes.Contains("memberOf"))
                {
                    groups = entry.Attributes["memberOf"]
                        .GetValues(typeof(string))
                        .Cast<string>()
                        .Select(dn => dn.Split(',')[0].Replace("CN=", ""))
                        .ToList();
                }

                return new DirectoryUser
                {
                    Username = sam,
                    DistinguishedName = entry.DistinguishedName,
                    DisplayName = entry.Attributes["displayName"]?[0]?.ToString(),
                    Email = entry.Attributes["mail"]?[0]?.ToString(),
                    Phone = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                    Department = entry.Attributes["department"]?[0]?.ToString(),
                    Title = entry.Attributes["title"]?[0]?.ToString(),
                    Groups = groups
                };
            });
        }

        public async Task<IReadOnlyCollection<DirectorySearchResult>> SearchUsersAsync(LdapConnection connection,UserSearchCriteria reqBody)
        {
            return await Task.Run(() =>
            {
                // 1️⃣ Build LDAP filter
                var filterParts = new List<string>();

                foreach (var (attribute, rawValue) in reqBody.Filters)
                {
                    if (rawValue == "*")
                    {
                        filterParts.Add($"({attribute}=*)");
                        continue;
                    }

                    var escaped = rawValue
                        .Replace("\\", "\\5c")
                        .Replace("*", "\\2a")
                        .Replace("(", "\\28")
                        .Replace(")", "\\29")
                        .Replace("\0", "\\00");

                    filterParts.Add($"({attribute}={escaped})");
                }

                var ldapFilter = filterParts.Count switch
                {
                    0 => "(objectClass=*)",
                    1 => filterParts[0],
                    _ => $"(&{string.Join("", filterParts)})"
                };

                // 2️⃣ LDAP search request
                var request = new SearchRequest(
                    reqBody.BaseDn!,
                    ldapFilter,
                    reqBody.Scope,
                    reqBody.Attributes.ToArray()
                )
                {
                    SizeLimit = reqBody.MaxResults
                };

                var response = (SearchResponse)connection.SendRequest(request);
                var results = new List<DirectorySearchResult>();

                // 3️⃣ Map results
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var result = new DirectorySearchResult
                    {
                        DistinguishedName = entry.DistinguishedName,
                        Username = entry.Attributes["sAMAccountName"]?[0]?.ToString()
                                   ?? "Unavailable"
                    };

                    foreach (var attr in reqBody.Attributes)
                    {
                        if (!entry.Attributes.Contains(attr)) continue;

                        var value = entry.Attributes[attr]?[0]?.ToString();
                        result.Attributes[attr] =
                            string.IsNullOrWhiteSpace(value) ? "Unavailable" : value;
                    }

                    results.Add(result);
                }

                return results;
            });
        }


        public async Task<IEnumerable<string>> GetUserGroupsAsync(LdapConnection connection, string username)
        {
            var samAccountName = username.Contains("@")
                    ? username.Split('@')[0]
                    : username;
            return await Task.Run(() => {
                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(sAMAccountName={samAccountName})",
                    SearchScope.Subtree,
                    "memberOf"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                if (entry == null)
                {
                    return Enumerable.Empty<string>();
                }

                // checks whether the user is 'member of any group' or not
                if (!entry.Attributes.Contains("memberOf") || entry.Attributes["memberOf"] == null)
                {
                    return Enumerable.Empty<string>();
                }
                var groups = entry.Attributes["memberOf"]
                    .GetValues(typeof(string))
                    .Cast<string>()
                    .Select(dn => dn.Split(',')[0].Replace("CN=", "")) // Extract CN from DN
                    .ToList();

                return groups;
            });
        }
          
    }
}
