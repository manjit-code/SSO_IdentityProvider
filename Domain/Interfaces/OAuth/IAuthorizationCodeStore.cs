using SSO_IdentityProvider.Domain.Entities.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Interfaces.OAuth
{
    public interface IAuthorizationCodeStore
    {
        void Store(AuthorizationCode authorizationCode);
        AuthorizationCode? Take(string code); // "Take" means retrieve and remove
    }
}
