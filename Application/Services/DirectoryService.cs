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
using Microsoft.Extensions.Options;

namespace SSO_IdentityProvider.Application.Services
{
    public class DirectoryService
    {
        private readonly IUserRepository _userRepository;
        private readonly LdapSettings _settings;
        private readonly ILdapAuthenticator _ldapAuthenticator;

        public DirectoryService(IUserRepository userRepository,IOptions<LdapSettings> options, ILdapAuthenticator ldapAuthenticator)
        {
            _userRepository = userRepository;
            _settings = options.Value;
            _ldapAuthenticator = ldapAuthenticator;
        }

        public async Task<DirectoryUser> GetMyProfileAsync(string username)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccount();
            if (connection == null)
            {
                throw new UnauthorizedAccessException("Invalid username or password.");
            }
            var user = await _userRepository.GetMyProfileAsync(connection, username)
                ?? throw new UnauthorizedAccessException("User not found in directory");

            return user;
        }


        public async Task<IReadOnlyCollection<DirectorySearchResult>> SearchUsersAsync(UserSearchCriteria request)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccount();
            if (connection == null)
            {
                throw new UnauthorizedAccessException("Invalid Service Account Credential.");
            }

            var baseDn = string.IsNullOrWhiteSpace(request.BaseDn)
                ? _settings.BaseDn
                : request.BaseDn;

            var maxResults = Math.Min(request.MaxResults, 100);
            return await _userRepository.SearchUsersAsync(connection, request);
        }

        public async Task UpdateMyProfileAsync(string username, UpdateMyProfile profile)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccount();

            var user = await _userRepository.GetByUsernameAsync(connection, username)
                ?? throw new UnauthorizedAccessException("User not found");

            await _userRepository.UpdateUserProfileAsync(
                connection,
                user.DistinguishedName,
                profile
            );
        }
    }
}
