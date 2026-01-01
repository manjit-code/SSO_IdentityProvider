using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Infrastructure.Configuration
{
    public class LdapSettings
    {
        // host, port, useSSL, Base DN, Domain etc.
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; }
        public bool UseSsl { get; set; }
        public string BaseDn { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;

        public int PortS { get; set; }
        public bool UseSslS { get; set; }
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;
    }
}
