using Esyasoft.Ldap.Gateway.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Interfaces
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user, IEnumerable<string> roles, IReadOnlyCollection<string> scopes);

        // OIDC
        string GenerateIdToken(User user,string clientId,string nonce,DateTime issuedAt, IReadOnlyCollection<string> scopes);
    }
}