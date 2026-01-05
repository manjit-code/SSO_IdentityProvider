using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class CreateUserCommand
    {
        public string FullName { get; set; } = string.Empty;
        public string DepartmentOu { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string ManagerDn { get; set; } = string.Empty;
        public string TelephoneNumber { get; set; } = string.Empty;
        public string? City { get; set; } 
        public string? State { get; set; }
        public string? PostalCode { get; set; }
    }
}
