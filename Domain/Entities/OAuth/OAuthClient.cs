using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities.OAuth
{
    public class OAuthClient
    {
        public string ClientId { get; set; } = string.Empty;
        public string ClientSecret { get; set; } = string.Empty;
        public IReadOnlyCollection<string> RedirectUris { get; set; } = Array.Empty<string>();
        public IReadOnlyCollection<string> AllowedScopes { get; set; } = Array.Empty<string>();
    }
}