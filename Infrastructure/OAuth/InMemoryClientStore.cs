using SSO_IdentityProvider.Domain.Entities.OAuth;
using SSO_IdentityProvider.Domain.Interfaces.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Infrastructure.OAuth
{
    public class InMemoryClientStore : IClientStore
    {
        private readonly List<OAuthClient> _clients = [
                new OAuthClient{
                    ClientId = "sample-client",
                    ClientSecret = "sample-secret",
                    RedirectUris = new[] {"http://localhost:5173"},
                    AllowedScopes = new[] {"openid", "profile"}
                },
                new OAuthClient
                {
                    ClientId = "react-app-a",
                    RedirectUris = new[] { "http://localhost:5173/callback" },
                    AllowedScopes = new[] { "openid", "profile", "email" }
                },
                new OAuthClient
                {
                    ClientId = "react-app-b",
                    RedirectUris = new[] { "http://localhost:5174/callback" },
                    AllowedScopes = new[] { "openid", "profile", "email" }
                }
            ];
        public OAuthClient? FindClientById(string clientId)
        {
            return _clients.FirstOrDefault(c => c.ClientId == clientId);
        }


    }
}