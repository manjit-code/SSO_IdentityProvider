using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities.OAuth
{
    public class IntrospectionResult
    {
        public bool Active { get; set; }

        public string? Sub { get; set; }
        public string? ClientId { get; set; }
        public string? Scope { get; set; }

        public long? Exp { get; set; }
        public long? Iat { get; set; }
        public string? Iss { get; set; }
    }
}
