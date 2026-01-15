using SSO_IdentityProvider.Domain.Entities.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Interfaces.OAuth
{
    public interface IRefreshTokenStore
    {
        void Store(RefreshToken token);
        RefreshToken? Take(string token);

        void Revoke(string token);
        void RevokeAllForUser(string username);
    }
}