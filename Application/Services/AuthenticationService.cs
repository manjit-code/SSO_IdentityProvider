using Esyasoft.Ldap.Gateway.Domain.Entities;
using Esyasoft.Ldap.Gateway.Domain.Interfaces;
using System.DirectoryServices.Protocols;

namespace Esyasoft.Ldap.Gateway.Application.Services
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

        public async Task<LoginDetailedResult> LoginDetailedAsync(string username, string password)
        {
            try
            {
                // ── Step 1: Check user exists ─────────────────────────────────
                using var serviceConnection = _ldapAuthenticator.BindAsServiceAccount();
                var user = await _userRepository.GetByUsernameAsync(serviceConnection, username);

                if (user == null)
                {
                    return LoginDetailedResult.UserNotFound();
                }

                // ── Step 2: Check lockout BEFORE attempting BIND ──────────────
                // Reading ppolicy attributes via service account.
                // If already locked → return immediately, do not BIND.
                var (isLocked, remainingSeconds) = await _userRepository.ReadLockoutStatusAsync(user.DistinguishedName);

                if (isLocked) return LoginDetailedResult.AccountLocked(remainingSeconds);

                // ── Step 3: BIND as user (password verification) ──────────────
                LdapConnection? userConnection = null;
                try
                {
                    userConnection = await _ldapAuthenticator.BindAsUserAsync(username, password);
                }
                catch (UnauthorizedAccessException ex)
                    when (ex.Message.Contains("locked",StringComparison.OrdinalIgnoreCase))
                {
                    // BIND triggered a fresh lockout — re-read remaining time
                    var freshLockout = await _userRepository.ReadLockoutStatusAsync(user.DistinguishedName);
                    return LoginDetailedResult.AccountLocked(freshLockout.IsLocked ? freshLockout.RemainingSeconds : null);
                }
                catch (UnauthorizedAccessException)
                {
                    // Wrong password
                    return LoginDetailedResult.WrongPassword();
                }

                if (userConnection == null)
                {
                    // BindAsUserAsync returns null for wrong password
                    return LoginDetailedResult.WrongPassword();
                }

                // ── Step 4: Check if account is disabled ──────────────────────
                // OpenLDAP uses "Account Status: Disabled" in the description field.
                // This is different from ppolicy lockout — it is a manual disable.
                var profile = await _userRepository.GetMyProfileAsync(
                    serviceConnection, username);

                userConnection.Dispose();

                if (profile != null &&
                    profile.IsEnabled.HasValue &&
                    !profile.IsEnabled.Value)
                {
                    // Treat manual disable the same as permanent lockout
                    return LoginDetailedResult.AccountLocked(-1);
                }

                // ── Step 5: Success ───────────────────────────────────────────
                return LoginDetailedResult.Success();
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[AuthService.LoginDetailedAsync] Unexpected error for " +
                    $"{username}: {ex.Message}");
                return LoginDetailedResult.ProviderError();
            }
        }

        /// <summary>
        /// Returns lockout status without attempting a password check.
        /// Called by GET /api/Auth/lockout-status/{username}.
        /// </summary>
        public async Task<LoginDetailedResult> GetLockoutStatusAsync(string username)
        {
            try
            {
                using var serviceConnection = _ldapAuthenticator.BindAsServiceAccount();
                var user = await _userRepository.GetByUsernameAsync(
                    serviceConnection, username);

                if (user == null)
                    return LoginDetailedResult.UserNotFound();

                var (isLocked, remainingSeconds) =
                    await _userRepository.ReadLockoutStatusAsync(user.DistinguishedName);

                return isLocked
                    ? LoginDetailedResult.AccountLocked(remainingSeconds)
                    : LoginDetailedResult.NotLocked();
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[AuthService.GetLockoutStatusAsync] Error for {username}: " +
                    $"{ex.Message}");
                return LoginDetailedResult.ProviderError();
            }
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
