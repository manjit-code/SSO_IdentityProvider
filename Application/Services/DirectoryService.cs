using Microsoft.Extensions.Options;
using Esyasoft.Ldap.Gateway.Domain.Entities;
using Esyasoft.Ldap.Gateway.Domain.Interfaces;
using Esyasoft.Ldap.Gateway.Infrastructure.Configuration;

namespace Esyasoft.Ldap.Gateway.Application.Services
{
    public class DirectoryService
    {
        private readonly IUserRepository _userRepository;
        private readonly LdapSettings _settings;
        private readonly ILdapAuthenticator _ldapAuthenticator;

        public DirectoryService(IUserRepository userRepository, IOptions<LdapSettings> options, ILdapAuthenticator ldapAuthenticator)
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

            await _userRepository.UpdateUserProfileAsync(user.DistinguishedName, profile);
        }

        public async Task<CreateUserResponse> CreateUserAsync(CreateUserCommand newUser)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();
            if (connection == null)
            {
                throw new UnauthorizedAccessException("Invalid Service Account Credential.");
            }
            var userDn = await _userRepository.CreateUserAsync(newUser);
            return userDn;
        }

        public async Task UpdateUserAsAdminAsync(AdminUpdateUserCommand command)
        {
            await _userRepository.UpdateUserAsAdminAsync(command);
        }

        public async Task UpdateUserStatusAsync(UpdateUserStatusCommand command)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();
            if (connection == null)
                throw new UnauthorizedAccessException("Invalid service account.");

            await _userRepository.UpdateUserStatusAsync(command);
        }
        public async Task CreateOuAsync(CreateOuCommand command)
        {
            await _userRepository.CreateOuAsync(command);
        }

        public async Task DeleteOuAsync(DeleteOuCommand command)
        {
            await _userRepository.DeleteOuAsync(command);
        }

        public async Task<DirectoryUser> GetUserInfoAsync(string username)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccount();
            if (connection == null) throw new UnauthorizedAccessException();

            var user = await _userRepository.GetMyProfileAsync(connection, username) ?? throw new UnauthorizedAccessException("User not found");

            return user;
        }

        public async Task DeleteUserAsync(string distinguishedName)
        {
            if (string.IsNullOrWhiteSpace(distinguishedName))
                throw new ArgumentException(
                    "Distinguished name cannot be empty.", nameof(distinguishedName));

            await _userRepository.DeleteUserAsync(distinguishedName);
        }

        public async Task<CreateConsumerResult> CreateConsumerAsync(CreateConsumerCommand command)
        {
            return await _userRepository.CreateConsumerAsync(command);
        }

        public async Task UpdateConsumerAsync(UpdateConsumerCommand command)
        {
            await _userRepository.UpdateConsumerAsync(command);
        }

        public async Task DeleteConsumerAsync(DeleteConsumerCommand command)
        {
            await _userRepository.DeleteConsumerAsync(command);
        }

    }
}