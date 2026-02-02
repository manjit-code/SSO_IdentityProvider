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
        public int Port { get; set; } = 636;
        public bool UseSsl { get; set; } = true;
        public string BaseDn { get; set; } = string.Empty;
        public string Domain { get; set; } = string.Empty;
        public string username { get; set; } = string.Empty;
        public string password { get; set; } = string.Empty;


        // Add account status attribute configuration
        public string AccountStatusAttribute { get; set; } = "description";
        public string EnabledStatusValue { get; set; } = "Account Status: Active";
        public string DisabledStatusValue { get; set; } = "Account Status: Disabled";
    }
}
