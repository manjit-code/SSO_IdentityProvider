using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Entities.Password
{
    public class PasswordValidationResponse
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new();
    }
}
