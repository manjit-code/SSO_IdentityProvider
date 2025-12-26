using SSO_IdentityProvider.Domain.Interfaces;

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
            if(connection == null)
            {
                throw new UnauthorizedAccessException("Invalid username or password.");
            }
            Console.WriteLine($"Connection : {connection}");

            var user = await _userRepository.GetByUsernameAsync(connection, username) ?? throw new UnauthorizedAccessException();
            Console.WriteLine($"User: {user}");

            var roles = await _userRepository.GetUserGroupsAsync(connection,username);
            Console.WriteLine($"Roles: {roles}");

            return _tokenService.GenerateAccessToken(user, roles);
        }
    }
}
