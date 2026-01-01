using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class UserSearchCriteria
    {
        public string? BaseDn { get; set; }

        public Dictionary<string, string>? Filters { get; set; }

        public List<string>? Attributes { get; set; }

        public SearchScope Scope { get; set; } = SearchScope.Subtree;

        public int MaxResults { get; set; } = 100;
    }
}
