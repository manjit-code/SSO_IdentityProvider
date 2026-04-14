using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Entities
{
    public class AdminUpdateUserCommand
    {
        public string Email { get; set; } = string.Empty;
        public string? Department { get; set; }
        public string? ManagerEmail { get; set; }
        public string? Title { get; set; }
    }
}