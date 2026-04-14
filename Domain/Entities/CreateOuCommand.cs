using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Entities
{
    public class CreateOuCommand
    {
        public string ParentOuDn { get; set; } = string.Empty;
        public string NewOuName { get; set; } = string.Empty;
    }
}
