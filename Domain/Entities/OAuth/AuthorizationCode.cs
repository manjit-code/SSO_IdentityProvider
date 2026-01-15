using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities.OAuth
{
    public class AuthorizationCode
    {
        public string Code { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;

        // PKCE
        public string CodeChallenge { get; set; } = string.Empty;
        public string CodeChallengeMethod { get; set; } = "S256";

        public DateTime ExpiresAt { get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiresAt;
    }
}