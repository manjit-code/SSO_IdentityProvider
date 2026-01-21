using SSO_IdentityProvider.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Interfaces
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user, IEnumerable<string> roles, IReadOnlyCollection<string> scopes);

        // OIDC
        string GenerateIdToken(User user,string clientId,string nonce,DateTime issuedAt, IReadOnlyCollection<string> scopes);
    }
}