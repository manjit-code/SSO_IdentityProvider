using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Interfaces
{
    public interface ILdapAuthenticator
    {
        Task<LdapConnection?> BindAsUserAsync(string username, string password);
        LdapConnection BindAsServiceAccount();

        LdapConnection BindAsServiceAccountForWrite();
        LdapConnection BindAsInfraServiceAccountForWrite();
    }
}
