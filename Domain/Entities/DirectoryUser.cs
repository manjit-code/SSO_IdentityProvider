using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class DirectoryUser
    {
        public string Username { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public string? Phone { get; set; }
        public string? Department { get; set; }
        public string? Manager { get; set; }
        public string? Title { get; set; }
        public IReadOnlyCollection<string> Groups { get; set; } = Array.Empty<string>();
        public bool? IsEnabled { get; set; } = true;
    }
}
