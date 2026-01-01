using SSO_IdentityProvider.Domain.Entities;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Interfaces
{
    public interface IUserRepository
    {
        Task<User?> GetByUsernameAsync(LdapConnection connection,string username);
        Task<IEnumerable<string>> GetUserGroupsAsync(LdapConnection connection, string username);

        Task<DirectoryUser?> GetMyProfileAsync(LdapConnection connection, string username);

        Task<IReadOnlyCollection<DirectorySearchResult>> SearchUsersAsync(LdapConnection connection, UserSearchCriteria reqBody);

        Task UpdateUserProfileAsync(LdapConnection connection, string userDn, UpdateMyProfile profile);
    }
}
