using Microsoft.Extensions.Options;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Infrastructure.Mapper
{
    public class AttributeMapper
    {
        private readonly LdapSettings _settings;

        public AttributeMapper(IOptions<LdapSettings> options)
        {
            _settings = options.Value;
        }

        public string MapAttribute(string genericAttribute)
        {
            if (_settings.LdapType == LdapType.ActiveDirectory)
            {
                return genericAttribute switch
                {
                    "Username" => _settings.AttributeMappings.SamAccountName,
                    "Email" => _settings.AttributeMappings.UserPrincipalName,
                    "DisplayName" => "displayName",
                    "Department" => "department",
                    "Manager" => "manager",
                    "Title" => "title",
                    "Phone" => "telephoneNumber",
                    "MemberOf" => "memberOf",
                    "Password" => "unicodePwd",
                    "SamAccountName" => "sAMAccountName",
                    "UserPrincipalName" => "userPrincipalName",
                    "AccountStatus" => "userAccountControl",
                    "ObjectClassUser" => "user",
                    "ObjectClassOu" => "organizationalUnit",
                    _ => genericAttribute
                };
            }
            else
            {
                return genericAttribute switch
                {
                    "Username" => _settings.AttributeMappings.UsernameAttribute,
                    "Email" => _settings.AttributeMappings.EmailAttribute,
                    "DisplayName" => _settings.AttributeMappings.DisplayNameAttribute,
                    "Department" => _settings.AttributeMappings.DepartmentAttribute,
                    "Manager" => _settings.AttributeMappings.ManagerAttribute,
                    "Title" => _settings.AttributeMappings.TitleAttribute,
                    "Phone" => _settings.AttributeMappings.PhoneAttribute,
                    "MemberOf" => _settings.AttributeMappings.MemberOfAttribute,
                    "Password" => _settings.AttributeMappings.PasswordAttribute,
                    "SamAccountName" => _settings.AttributeMappings.SamAccountName,
                    "UserPrincipalName" => _settings.AttributeMappings.UserPrincipalName,
                    "AccountStatus" => _settings.AttributeMappings.AccountStatusAttribute,
                    "ObjectClassUser" => _settings.AttributeMappings.ObjectClassUser,
                    "ObjectClassOu" => _settings.AttributeMappings.ObjectClassOu,
                    _ => genericAttribute
                };
            }
        }

        public string GetUserObjectClass() => _settings.LdapType == LdapType.ActiveDirectory
            ? "user"
            : _settings.AttributeMappings.ObjectClassUser;

        public string GetOuObjectClass() => _settings.LdapType == LdapType.ActiveDirectory
            ? "organizationalUnit"
            : _settings.AttributeMappings.ObjectClassOu;

        public string GetUserSearchFilter() => _settings.LdapType == LdapType.ActiveDirectory
            ? "(objectClass=user)"
            : _settings.AttributeMappings.UserSearchFilter;

        public string GetOuSearchFilter() => _settings.LdapType == LdapType.ActiveDirectory
            ? "(objectClass=organizationalUnit)"
            : _settings.AttributeMappings.OuSearchFilter;

        public bool IsActiveDirectory => _settings.LdapType == LdapType.ActiveDirectory;
        public bool IsOpenLdap => _settings.LdapType == LdapType.OpenLDAP;

        public bool UseAdAccountControl => _settings.LdapType == LdapType.ActiveDirectory
            && _settings.AttributeMappings.UseAdUserAccountControl;

        // Helper method to get the appropriate username attribute for search
        public string GetUsernameSearchAttribute()
        {
            return IsActiveDirectory
                ? "sAMAccountName"
                : _settings.AttributeMappings.UsernameAttribute;
        }

        // Helper method to get the appropriate email attribute for search
        public string GetEmailSearchAttribute()
        {
            return IsActiveDirectory
                ? "userPrincipalName"
                : _settings.AttributeMappings.EmailAttribute;
        }

        // Helper to get distinguished name format
        public string GetUserRdn(string username)
        {
            return IsActiveDirectory
                ? $"CN={username}"
                : $"uid={username}";
        }

        // Helper for AD account control values
        public string GetAdAccountControlValue(bool enabled)
        {
            return enabled
                ? _settings.AttributeMappings.AdEnabledAccountValue.ToString()
                : _settings.AttributeMappings.AdDisabledAccountValue.ToString();
        }

        // Helper for parsing group DNs (AD uses different DN format)
        public string ExtractGroupNameFromDn(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return string.Empty;

            if (IsActiveDirectory)
            {
                // AD: CN=GroupName,OU=Groups,DC=corp,DC=local
                var parts = dn.Split(',');
                foreach (var part in parts)
                {
                    if (part.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    {
                        return part.Substring(3);
                    }
                }
            }
            else
            {
                // OpenLDAP: cn=groupname,ou=groups,dc=corp,dc=local
                var parts = dn.Split(',');
                foreach (var part in parts)
                {
                    if (part.StartsWith("cn=", StringComparison.OrdinalIgnoreCase))
                    {
                        return part.Substring(3);
                    }
                }
            }

            return dn;
        }

        public string FormatSearchValue(string genericAttribute, string value)
        {
            if (string.IsNullOrEmpty(value)) return value;

            var attrLower = genericAttribute.ToLowerInvariant();

            // Only handle status for AD with account control
            if ((attrLower == "status" || attrLower == "accountstatus") &&
                _settings.LdapType == LdapType.ActiveDirectory &&
                UseAdAccountControl)
            {
                var statusValue = value.Equals("enabled", StringComparison.OrdinalIgnoreCase)
                    || value.Equals("active", StringComparison.OrdinalIgnoreCase);
                return GetAdAccountControlValue(statusValue);
            }

            return value;
        }
    }
}