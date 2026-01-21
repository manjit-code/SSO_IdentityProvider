using SSO_IdentityProvider.Domain.Entities.OAuth;
using SSO_IdentityProvider.Domain.Interfaces.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Infrastructure.OAuth
{
    public class InMemoryAuthorizationCodeStore : IAuthorizationCodeStore
    {
        private readonly Dictionary<string, AuthorizationCode> _authorizationCodes = new();

        public void Store(AuthorizationCode authorizationCode)
        {
            _authorizationCodes[authorizationCode.Code] = authorizationCode;
        }

        public AuthorizationCode? Take(string code)
        {
            if (!_authorizationCodes.TryGetValue(code, out var authorizationCode))
            {
                return null;
            }

            _authorizationCodes.Remove(code);
            return authorizationCode;
        }
    }
}
