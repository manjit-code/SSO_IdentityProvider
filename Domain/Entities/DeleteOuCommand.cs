using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class DeleteOuCommand
    {
        public string OuDn { get; set; } = string.Empty;
        public bool CascadeDelete { get; set; }
    }
}
