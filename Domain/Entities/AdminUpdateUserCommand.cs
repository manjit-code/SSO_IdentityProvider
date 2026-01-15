using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class AdminUpdateUserCommand
    {
        public string Email { get; set; } = string.Empty;
        public string? Department { get; set; }
        public string? ManagerEmail { get; set; }
        public string? Title { get; set; }
    }
}