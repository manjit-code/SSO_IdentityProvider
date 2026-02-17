using SSO_IdentityProvider.Infrastructure.Configuration;

namespace SSO_IdentityProvider.API.DTOs
{
    public class UserAttributesRequest
    {

        private readonly LdapType? _ldapType;

        public UserAttributesRequest() { }

        public UserAttributesRequest(LdapType? ldapType = null)
        {
            _ldapType = ldapType;
        }

        public bool IncludeAll { get; set; }
        public bool IncludeUsername { get; set; } = true;
        public bool IncludeDistinguishedName { get; set; } = true;
        public bool IncludeDisplayName { get; set; } = true;
        public bool IncludeEmail { get; set; } = true;
        public bool IncludeDepartment { get; set; }
        public bool IncludeTitle { get; set; }
        public bool IncludePhone { get; set; }
        public bool IncludeManager { get; set; }
        public bool IncludeAccountStatus { get; set; }
        public bool IncludeGroups { get; set; }
        public bool IncludeAddress { get; set; }
    }
}
