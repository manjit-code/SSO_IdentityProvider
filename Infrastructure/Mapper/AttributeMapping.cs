using SSO_IdentityProvider.Infrastructure.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Infrastructure.Mapper
{
    public class AttributeMapping
    {
        public string UsernameAttribute { get; set; } = "uid";
        public string EmailAttribute { get; set; } = "mail";
        public string DisplayNameAttribute { get; set; } = "cn";
        public string DepartmentAttribute { get; set; } = "description"; // For OpenLDAP
        public string ManagerAttribute { get; set; } = "manager";
        public string TitleAttribute { get; set; } = "title";
        public string PhoneAttribute { get; set; } = "telephoneNumber";
        public string MemberOfAttribute { get; set; } = "memberOf";
        public string ObjectClassUser { get; set; } = "inetOrgPerson";
        public string ObjectClassOu { get; set; } = "organizationalUnit";
        public string PasswordAttribute { get; set; } = "userPassword";

        // AD-specific attributes
        public string SamAccountName { get; set; } = "sAMAccountName";
        public string UserPrincipalName { get; set; } = "userPrincipalName";
        public string AccountStatusAttribute { get; set; } = "userAccountControl";

        // AD-specific properties (only used when LdapType = ActiveDirectory)
        public bool UseAdUserAccountControl { get; set; } = false;
        public int AdEnabledAccountValue { get; set; } = 512; // Normal account
        public int AdDisabledAccountValue { get; set; } = 514; // Disabled account

        // Search filters
        public string UserSearchFilter { get; set; } = "(objectClass=inetOrgPerson)";
        public string OuSearchFilter { get; set; } = "(objectClass=organizationalUnit)";
    }
}
