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

        public async Task<IEnumerable<string>> GetUserGroupsAsync(LdapConnection connection,string username)
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
