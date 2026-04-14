using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Entities.Password
{
    public class OtpResponse
    {
        public string Message { get; set; } = string.Empty;
        public string? Otp { get; set; } // only in development
    }
}
