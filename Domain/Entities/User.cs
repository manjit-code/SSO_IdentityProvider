using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        //public IReadOnlyCollection<string> Roles { get; set; } = Array.Empty<string>();
    }
}
