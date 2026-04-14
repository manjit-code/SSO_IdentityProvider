using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Entities
{
    public class DeleteConsumerCommand
    {
        public string Username { get; set; } = string.Empty;
        public string? DeletedBy { get; set; }
    }
}
