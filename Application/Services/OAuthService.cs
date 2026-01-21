using SSO_IdentityProvider.Domain.Entities.OAuth;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Domain.Interfaces.OAuth;
using SSO_IdentityProvider.Infrastructure.OAuth;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Formats.Asn1.AsnWriter;

namespace SSO_IdentityProvider.Application.Services
{
    public class OAuthService
    {
        private readonly IAuthorizationCodeStore _authorizationCodeStore;
        private readonly IClientStore _clientStore;
        private readonly ITokenService _tokenService;
        private readonly ILdapAuthenticator _ldapAuthenticator;
        private readonly IUserRepository _userRepository;
        private readonly IRefreshTokenStore _refreshTokenStore;


        public OAuthService(IAuthorizationCodeStore authorizationCodeStore, IClientStore clientStore, ITokenService tokenService, IUserRepository userRepository, ILdapAuthenticator ldapAuthenticator, IRefreshTokenStore refreshTokenStore)
        {
            _authorizationCodeStore = authorizationCodeStore;
            _clientStore = clientStore;
            _tokenService = tokenService;
            _userRepository = userRepository;
            _ldapAuthenticator = ldapAuthenticator;
            _refreshTokenStore = refreshTokenStore;
        }

        public string GenerateAuthorizationCode(string clientId, string redirectUri, string username, string codeChallenge, string codeChallengeMethod, string scope,string? nonce)
        {
            if (string.IsNullOrWhiteSpace(codeChallenge))
            {
                throw new Exception("PKCE code_challenge required");
            }
            if (codeChallengeMethod != "S256")
            {
                throw new Exception("Unsupported code challenge method. Only supports S256");
            }

            var client = _clientStore.FindClientById(clientId) ?? throw new Exception("Invalid client ID");
            if (!client.RedirectUris.Contains(redirectUri))
            {
                throw new Exception("Invalid redirect URI");
            }

            var code = Guid.NewGuid().ToString("N"); // simple code generation

            // check allowed scopes
            var requestedScopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();

            // OAuth requires openid for OIDC
            if (!requestedScopes.Contains("openid"))
            {
                throw new UnauthorizedAccessException(
                    "Missing required scope: openid"
                );
            }

            // Validate against client allowed scopes
            var unauthorizedScopes = requestedScopes.Except(client.AllowedScopes).ToList();

            if (unauthorizedScopes.Any())
            {
                throw new UnauthorizedAccessException(
                    $"Client '{clientId}' is not allowed to request scopes: {string.Join(", ", unauthorizedScopes)}"
                );
            }


            _authorizationCodeStore.Store(
                new AuthorizationCode
                {
                    Code = code,
                    ClientId = clientId,
                    RedirectUri = redirectUri,
                    Username = username,
                    CodeChallenge = codeChallenge,
                    CodeChallengeMethod = codeChallengeMethod,
                    Scope = string.Join(" ", requestedScopes),
                    Nonce = nonce,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5)
                }
            );

            return code;
        }

        public (string accessToken, string refreshToken, string? idToken) ExchangeCodeForToken(string code, string clientId, string redirectUri, string codeVerifier)
        {
            var authCode = _authorizationCodeStore.Take(code) ?? throw new UnauthorizedAccessException();

            if (authCode.IsExpired || authCode.ClientId != clientId || authCode.RedirectUri != redirectUri)
                throw new UnauthorizedAccessException();

            ValidatePkce(codeVerifier, authCode.CodeChallenge);

            var connection = _ldapAuthenticator.BindAsServiceAccount();
            var user = _userRepository.GetByUsernameAsync(connection, authCode.Username).Result ?? throw new Exception("User not found");
            var roles = _userRepository.GetUserGroupsAsync(connection, authCode.Username).Result;
            var scopes = authCode.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
            var accessToken = _tokenService.GenerateAccessToken(user, roles,scopes);
            var refreshToken = CreateRefreshToken(user.UserName, clientId, scopes);

            _refreshTokenStore.Store(refreshToken);

            string? idToken = null;

            if (authCode.Scope.Split(' ').Contains("openid"))
            {
                idToken = _tokenService.GenerateIdToken(
                    user,
                    clientId,
                    authCode.Nonce ?? "",
                    DateTime.UtcNow,
                    scopes: scopes
                );
            }
            Console.WriteLine($"Verifier received: {codeVerifier}");
            Console.WriteLine($"Expected challenge: {authCode.CodeChallenge}");

            return (accessToken, refreshToken.Token, idToken);
        }

        private RefreshToken CreateRefreshToken(string username, string clientId, IReadOnlyCollection<string> scopes)
        {
            return new RefreshToken
            {
                Token = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                Username = username,
                ClientId = clientId,
                Scopes = scopes,
                ExpiresAt = DateTime.UtcNow.AddDays(14)
            };
        }

        public (string accessToken, string refreshToken) RefreshAccessToken(string refreshToken, string clientId)
        {
            var client = _clientStore.FindClientById(clientId) ?? throw new UnauthorizedAccessException("Invalid client ID");

            var storedToken = _refreshTokenStore.Take(refreshToken) ?? throw new UnauthorizedAccessException("Invalid refresh token");
            
            if (storedToken.IsRevoked) throw new UnauthorizedAccessException("Refresh token revoked");
            if (storedToken.IsExpired || storedToken.ClientId != clientId) throw new UnauthorizedAccessException("Expired refresh token");

            var connection = _ldapAuthenticator.BindAsServiceAccount();
            var user = _userRepository.GetByUsernameAsync(connection, storedToken.Username).Result!;
            var roles = _userRepository.GetUserGroupsAsync(connection, storedToken.Username).Result;
            
            var newAccessToken = _tokenService.GenerateAccessToken(user, roles,storedToken.Scopes);

            var newRefreshToken = CreateRefreshToken(user.UserName, clientId, storedToken.Scopes);
            _refreshTokenStore.Store(newRefreshToken);

            return (newAccessToken, newRefreshToken.Token);
        }

        private static void ValidatePkce(string verifier, string expectedChallenge)
        {
            if (string.IsNullOrWhiteSpace(verifier))
                throw new UnauthorizedAccessException("Missing PKCE verifier");

            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(verifier));

            var computedChallenge = Convert.ToBase64String(hash)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            if (!CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(computedChallenge),
                    Encoding.ASCII.GetBytes(expectedChallenge)))
            {
                throw new UnauthorizedAccessException("PKCE validation failed");
            }
        }



        public void RevokeRefreshToken(string refreshToken)
        {
            _refreshTokenStore.Revoke(refreshToken);
        }

        public void LogoutEverywhere(string username)
        {
            _refreshTokenStore.RevokeAllForUser(username);
        }

        public IntrospectionResult IntrospectToken(string token)
        {
            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(token))
                return IntrospectionResult.Inactive();

            JwtSecurityToken jwt;
            try
            {
                jwt = handler.ReadJwtToken(token);
            }
            catch
            {
                return IntrospectionResult.Inactive();
            }

            // 1️⃣ Expiry check
            if (jwt.ValidTo < DateTime.UtcNow)
                return IntrospectionResult.Inactive();

            var sub = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            if (string.IsNullOrWhiteSpace(sub))
                return IntrospectionResult.Inactive();

            // 2️⃣ Check global logout (refresh-token revocation)
            if (_refreshTokenStore is InMemoryRefreshTokenStore store)
            {
                if (store.IsUserGloballyLoggedOut(sub))
                    return IntrospectionResult.Inactive();
            }

            return IntrospectionResult.ActiveToken(jwt);
        }
    }
}
