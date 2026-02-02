using SSO_IdentityProvider.Domain.Interfaces;
using System.DirectoryServices.Protocols;

namespace SSO_IdentityProvider.Application.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IUserRepository _userRepository;
        private readonly ITokenService _tokenService;
        private readonly ILdapAuthenticator _ldapAuthenticator;

        public AuthenticationService(IUserRepository userRepository, ITokenService tokenService, ILdapAuthenticator ldapAuthenticator)
        {
            _userRepository = userRepository;
            _tokenService = tokenService;
            _ldapAuthenticator = ldapAuthenticator;
        }
        public async Task<string> AuthenticateAsync(string username, string password)
        {
            // follows separation of concerns
            var connection = await _ldapAuthenticator.BindAsUserAsync(username, password);
            if (connection == null)
            {
                throw new UnauthorizedAccessException("Invalid username or password.");
            }

            // check if account is disabled
            if (await IsAccountDisabled(username, connection))
            {
                throw new UnauthorizedAccessException("Account is disabled.");
            }

            var user = await _userRepository.GetByUsernameAsync(connection, username) ?? throw new UnauthorizedAccessException("User not found.");
            //Console.WriteLine($"User: {user}");

            var roles = await _userRepository.GetUserGroupsAsync(connection, username);
            //Console.WriteLine($"Roles: {roles}");

            var scopes = new List<string> { "openid"}; // default scopes
            return _tokenService.GenerateAccessToken(user, roles,scopes);
        }

        private async Task<bool> IsAccountDisabled(string username, LdapConnection connection)
        {
            try
            {
                var profile = await _userRepository.GetMyProfileAsync(connection, username);
                if (profile == null) return true;

                return !profile.IsEnabled.HasValue || !profile.IsEnabled.Value;
            }
            catch
            {
                return false;
            }
        }
    }
}
