using SSO_IdentityProvider.Domain.Entities.OAuth;
using SSO_IdentityProvider.Domain.Interfaces.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Infrastructure.OAuth
{
    public class InMemoryRefreshTokenStore : IRefreshTokenStore
    {
        private readonly Dictionary<string, RefreshToken> _store = new();

        public void Store(RefreshToken token)
        {
            _store[token.Token] = token;
        }

        public RefreshToken? Take(string token)
        {
            if (!_store.TryGetValue(token, out var refreshToken))
                return null;

            _store.Remove(token);
            return refreshToken;
        }

        public void Revoke(string token)
        {
            if (_store.TryGetValue(token, out var refreshToken))
            {
                refreshToken.IsRevoked = true;
            }
        }

        public void RevokeAllForUser(string username)
        {
            foreach (var token in _store.Values.Where(t => t.Username == username))
            {
                token.IsRevoked = true;
            }
        }
    }
}
