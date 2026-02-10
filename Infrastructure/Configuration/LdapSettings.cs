using SSO_IdentityProvider.Infrastructure.Mapper;
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


        public LdapType LdapType { get; set; } = LdapType.OpenLDAP;

        // Attribute mapping configuration
        public AttributeMapping AttributeMappings { get; set; } = new();

        // Helper properties for backward compatibility
        [Obsolete("Use AttributeMappings.AccountStatusAttribute instead")]
        public string AccountStatusAttribute => AttributeMappings.AccountStatusAttribute;

        [Obsolete("Use AttributeMappings.DepartmentAttribute instead")]
        public string DepartmentAttribute => AttributeMappings.DepartmentAttribute;
    }
}
