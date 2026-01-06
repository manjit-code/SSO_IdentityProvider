using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class CreateUserResponse
    {
        public string Username { get; set; } = string.Empty;
        public string InitialPassword { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
    }
}
