using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class UpdateUserStatusCommand
    {
        public string Email { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
    }
}
