using SSO_IdentityProvider.Domain.Entities.OAuth;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Domain.Interfaces.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

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

        public string GenerateAuthorizationCode(string clientId, string redirectUri, string username, string codeChallenge, string codeChallengeMethod)
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

            _authorizationCodeStore.Store(
                new AuthorizationCode
                {
                    Code = code,
                    ClientId = clientId,
                    RedirectUri = redirectUri,
                    Username = username,
                    CodeChallenge = codeChallenge,
                    CodeChallengeMethod = codeChallengeMethod,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5)
                }
            );

            return code;
        }

        public (string accessToken, string refreshToken) ExchangeCodeForToken(string code, string clientId, string redirectUri, string codeVerifier)
        {
            var authCode = _authorizationCodeStore.Take(code) ?? throw new UnauthorizedAccessException();

            if (authCode.IsExpired || authCode.ClientId != clientId || authCode.RedirectUri != redirectUri)
                throw new UnauthorizedAccessException();

            ValidatePkce(codeVerifier, authCode.CodeChallenge);

            var connection = _ldapAuthenticator.BindAsServiceAccount();
            var user = _userRepository.GetByUsernameAsync(connection, authCode.Username).Result ?? throw new Exception("User not found");
            var roles = _userRepository.GetUserGroupsAsync(connection, authCode.Username).Result;

            var accessToken = _tokenService.GenerateAccessToken(user, roles);
            var refreshToken = CreateRefreshToken(user.UserName, clientId);

            _refreshTokenStore.Store(refreshToken);

            return (accessToken, refreshToken.Token);
        }

        private RefreshToken CreateRefreshToken(string username, string clientId)
        {
            return new RefreshToken
            {
                Token = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                Username = username,
                ClientId = clientId,
                ExpiresAt = DateTime.UtcNow.AddDays(14)
            };
        }

        public (string accessToken, string refreshToken) RefreshAccessToken(string refreshToken, string clientId)
        {
            var client = _clientStore.FindClientById(clientId) ?? throw new UnauthorizedAccessException("Invalid client ID");

            var storedToken = _refreshTokenStore.Take(refreshToken) ?? throw new UnauthorizedAccessException("Invalid refresh token");

            if (storedToken.IsExpired || storedToken.ClientId != clientId) throw new UnauthorizedAccessException("Expired refresh token");

            var connection = _ldapAuthenticator.BindAsServiceAccount();
            var user = _userRepository.GetByUsernameAsync(connection, storedToken.Username).Result!;
            var roles = _userRepository.GetUserGroupsAsync(connection, storedToken.Username).Result;

            var newAccessToken = _tokenService.GenerateAccessToken(user, roles);

            var newRefreshToken = CreateRefreshToken(user.UserName, clientId);
            _refreshTokenStore.Store(newRefreshToken);

            return (newAccessToken, newRefreshToken.Token);
        }

        private static void ValidatePkce(string verifier, string expectedChallenge)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(verifier));

            var computedChallenge = Convert.ToBase64String(hash)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

            if (computedChallenge != expectedChallenge)
                throw new UnauthorizedAccessException("PKCE validation failed");
        }


        public void RevokeRefreshToken(string refreshToken)
        {
            _refreshTokenStore.Revoke(refreshToken);
        }

        public void LogoutEverywhere(string username)
        {
            _refreshTokenStore.RevokeAllForUser(username);
        }

    }
}
