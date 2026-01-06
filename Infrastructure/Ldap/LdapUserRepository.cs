using Microsoft.Extensions.Options;
using SSO_IdentityProvider.Domain.Entities;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Infrastructure.Ldap
{
    public class LdapUserRepository : IUserRepository
    {
        private readonly LdapSettings _ldapSettings;
        private readonly ILdapAuthenticator _ldapAuthenticator;
        public LdapUserRepository(IOptions<LdapSettings> option, ILdapAuthenticator ldapAuthenticator)
        {
            _ldapSettings = option.Value;
            _ldapAuthenticator = ldapAuthenticator;
        }

        public async Task<User?> GetByUsernameAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() =>
            {

                var samAccountName = username.Contains("@")
                    ? username.Split('@')[0]
                    : username;
                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(sAMAccountName={samAccountName})",
                    SearchScope.Subtree,
                    "cn", "mail", "sAMAccountName"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                if (entry == null)
                {
                    return null;
                }

                var newUser = new User
                {
                    UserName = username,
                    DistinguishedName = entry.DistinguishedName
                };

                return newUser;
            });
        }

        public async Task<DirectoryUser?> GetMyProfileAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() =>
            {
                var sam = username.Contains("@")
                    ? username.Split('@')[0]
                    : username;

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(sAMAccountName={sam})",
                    SearchScope.Subtree,
                    "distinguishedName",
                    "displayName",
                    "mail",
                    "telephoneNumber",
                    "department",
                    "title",
                    "memberOf"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();

                if (entry == null) return null;

                var groups = new List<string>();
                if (entry.Attributes.Contains("memberOf"))
                {
                    groups = entry.Attributes["memberOf"]
                        .GetValues(typeof(string))
                        .Cast<string>()
                        .Select(dn => dn.Split(',')[0].Replace("CN=", ""))
                        .ToList();
                }

                return new DirectoryUser
                {
                    Username = sam,
                    DistinguishedName = entry.DistinguishedName,
                    DisplayName = entry.Attributes["displayName"]?[0]?.ToString(),
                    Email = entry.Attributes["mail"]?[0]?.ToString(),
                    Phone = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                    Department = entry.Attributes["department"]?[0]?.ToString(),
                    Title = entry.Attributes["title"]?[0]?.ToString(),
                    Groups = groups
                };
            });
        }

        public async Task<IReadOnlyCollection<DirectorySearchResult>> SearchUsersAsync(LdapConnection connection,UserSearchCriteria reqBody)
        {
            return await Task.Run(() =>
            {
                // 1️⃣ Build LDAP filter
                var filterParts = new List<string>();

                foreach (var (attribute, rawValue) in reqBody.Filters)
                {
                    if (rawValue == "*")
                    {
                        filterParts.Add($"({attribute}=*)");
                        continue;
                    }

                    var escaped = rawValue
                        .Replace("\\", "\\5c")
                        .Replace("*", "\\2a")
                        .Replace("(", "\\28")
                        .Replace(")", "\\29")
                        .Replace("\0", "\\00");

                    filterParts.Add($"({attribute}={escaped})");
                }

                var ldapFilter = filterParts.Count switch
                {
                    0 => "(objectClass=*)",
                    1 => filterParts[0],
                    _ => $"(&{string.Join("", filterParts)})"
                };

                // 2️⃣ LDAP search request
                var request = new SearchRequest(
                    reqBody.BaseDn!,
                    ldapFilter,
                    reqBody.Scope,
                    reqBody.Attributes.ToArray()
                )
                {
                    SizeLimit = reqBody.MaxResults
                };

                var response = (SearchResponse)connection.SendRequest(request);
                var results = new List<DirectorySearchResult>();

                // 3️⃣ Map results
                foreach (SearchResultEntry entry in response.Entries)
                {
                    var result = new DirectorySearchResult
                    {
                        DistinguishedName = entry.DistinguishedName,
                        Username = entry.Attributes["sAMAccountName"]?[0]?.ToString()
                                   ?? "Unavailable"
                    };

                    foreach (var attr in reqBody.Attributes)
                    {
                        if (!entry.Attributes.Contains(attr)) continue;

                        var value = entry.Attributes[attr]?[0]?.ToString();
                        result.Attributes[attr] =
                            string.IsNullOrWhiteSpace(value) ? "Unavailable" : value;
                    }

                    results.Add(result);
                }

                return results;
            });
        }


        public async Task<IEnumerable<string>> GetUserGroupsAsync(LdapConnection connection, string username)
        {
            var samAccountName = username.Contains("@")
                    ? username.Split('@')[0]
                    : username;
            return await Task.Run(() => {
                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(sAMAccountName={samAccountName})",
                    SearchScope.Subtree,
                    "memberOf"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                if (entry == null)
                {
                    return Enumerable.Empty<string>();
                }

                // checks whether the user is 'member of any group' or not
                if (!entry.Attributes.Contains("memberOf") || entry.Attributes["memberOf"] == null)
                {
                    return Enumerable.Empty<string>();
                }
                var groups = entry.Attributes["memberOf"]
                    .GetValues(typeof(string))
                    .Cast<string>()
                    .Select(dn => dn.Split(',')[0].Replace("CN=", "")) // Extract CN from DN
                    .ToList();

                return groups;
            });
        }

        public async Task UpdateUserProfileAsync(string userDn,UpdateMyProfile profile)
        {
            await Task.Run(() =>
            {
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();
                var modifications = new List<DirectoryAttributeModification>();
                void ReplaceIfProvided(string attr, string? value)
                {
                    if (string.IsNullOrWhiteSpace(value)) return;

                    var mod = new DirectoryAttributeModification
                    {
                        Name = attr,
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    mod.Add(value);
                    modifications.Add(mod);
                }

                
                ReplaceIfProvided("displayName", profile.DisplayName);
                ReplaceIfProvided("telephoneNumber", profile.TelephoneNumber);
                ReplaceIfProvided("streetAddress", profile.StreetAddress);
                ReplaceIfProvided("l", profile.City);
                ReplaceIfProvided("st", profile.State);
                ReplaceIfProvided("postalCode", profile.PostalCode);

                if (modifications.Any())
                {
                    var modifyRequest = new ModifyRequest(userDn, modifications.ToArray());
                    connection.SendRequest(modifyRequest);
                }

                if (!string.IsNullOrWhiteSpace(profile.NewPassword))
                {
                    
                    ChangePassword(connection, userDn, profile.NewPassword);
                }
            });
        }

        private static void ChangePassword(LdapConnection connection, string userDn, string newPassword)
        {
            try
            {
                var pwdBytes = Encoding.Unicode.GetBytes($"\"{newPassword}\"");

                var mod = new DirectoryAttributeModification
                {
                    Name = "unicodePwd",
                    Operation = DirectoryAttributeOperation.Replace
                };
                mod.Add(pwdBytes);

                var request = new ModifyRequest(userDn, mod);
                connection.SendRequest(request);
            }
            catch (DirectoryOperationException ex)
            {
                throw new InvalidOperationException(
                    "Password does not meet domain password policy.",
                    ex
                );
            }
        }

        
        public async Task<CreateUserResponse> CreateUserAsync(CreateUserCommand newUser)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

            var departmentOuDn = GetDepartmentOuDnAsync(connection, newUser.Department);

            var sAMAccountName = GenerateSamAccountName(newUser.FullName);
            if(UserExistsBySamAsync(connection, sAMAccountName))
            {
                throw new InvalidOperationException("User already exists.");
            }

            string? managerDn = null;
            if(!string.IsNullOrWhiteSpace(newUser.ManagerEmail))
            {
                managerDn = FindUserDn(connection, newUser.ManagerEmail);
                if (managerDn == null)
                {
                    throw new InvalidOperationException("Manager user does not exist.");
                }
            };

            if (!string.IsNullOrWhiteSpace(newUser.Country) && newUser.Country.Length != 2)
            {
                throw new InvalidOperationException(
                    "Country must be a 2-letter ISO code (e.g., IN, US, GB)."
                );
            }


            // Generate Credentials
            var upn = $"{sAMAccountName}@{_ldapSettings.Domain}";
            var email = upn;
            var userDn = $"CN={newUser.FullName},{departmentOuDn}";
            var password = GenerateStrongPassword();


            if (managerDn != null && managerDn.Equals(userDn, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "A user cannot be their own manager."
                );
            }

            // Create user -> disabled by default
            var nameParts = newUser.FullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var addRequest = new AddRequest(userDn, new DirectoryAttribute[]
            {
                new DirectoryAttribute("objectClass", new[] { "top", "person", "organizationalPerson", "user" }),
                new DirectoryAttribute("cn", newUser.FullName),
                new DirectoryAttribute("displayName", newUser.FullName),
                new DirectoryAttribute("givenName", nameParts[0]),
                new DirectoryAttribute("sn", nameParts.Length > 1 ? nameParts[^1] : nameParts[0]),
                new DirectoryAttribute("sAMAccountName", sAMAccountName),
                new DirectoryAttribute("userPrincipalName", upn),
                new DirectoryAttribute("mail", email),
                new DirectoryAttribute("department", newUser.Department),
                new DirectoryAttribute("title", newUser.Title),
                new DirectoryAttribute("telephoneNumber", newUser.TelephoneNumber),
                new DirectoryAttribute("userAccountControl", "514") // disabled account
            });

            if (managerDn != null)
            {
                addRequest.Attributes.Add(
                    new DirectoryAttribute("manager", managerDn)
                );
            }
            if( !string.IsNullOrWhiteSpace(newUser.StreetAddress))
            {
                addRequest.Attributes.Add(
                    new DirectoryAttribute("streetAddress", newUser.StreetAddress)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.City))
            {
                addRequest.Attributes.Add(
                    new DirectoryAttribute("l", newUser.City)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.State))
            {
                addRequest.Attributes.Add(
                    new DirectoryAttribute("st", newUser.State)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.PostalCode))
            {
                addRequest.Attributes.Add(
                    new DirectoryAttribute("postalCode", newUser.PostalCode)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.Country))
            {
                if (newUser.Country.Length != 2)
                    throw new InvalidOperationException(
                        "Country must be a 2-letter ISO code (e.g., IN, US)."
                    );

                addRequest.Attributes.Add(new DirectoryAttribute("c", newUser.Country.ToUpper()));
            }


            connection.SendRequest(addRequest);

            // Set password
            SetPassword(connection, userDn, password);

            // Enable account + password never expires
            var modifications = new DirectoryAttributeModification
            {
                Name = "userAccountControl",
                Operation = DirectoryAttributeOperation.Replace
            };
            modifications.Add("66048"); // Enabled + Password never expires
            connection.SendRequest(new ModifyRequest(userDn, modifications));

            return new CreateUserResponse
            {
                Username = sAMAccountName,
                InitialPassword = password,
                Email = email,
                DistinguishedName = userDn
            };
        }
        private static string GenerateStrongPassword()
        {
            // Define simple sets
            string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // Removed 'I', 'O' to avoid confusion
            string lower = "abcdefghijkmnopqrstuvwxyz"; // Removed 'l'
            string digits = "23456789";                 // Removed '0', '1'
            string specials = "!@#$%^&*";

            var random = new Random();

            // 1. Force one from each to satisfy "3 of 4" categories rule
            var chars = new List<char>
            {
                upper[random.Next(upper.Length)],
                lower[random.Next(lower.Length)],
                digits[random.Next(digits.Length)],
                specials[random.Next(specials.Length)]
            };

            // 2. Fill the rest to reach 12 characters (Recommended length)
            string all = upper + lower + digits + specials;
            for (int i = 0; i < 8; i++)
                chars.Add(all[random.Next(all.Length)]);

            // 3. Shuffle so the patterns aren't predictable
            return new string(chars.OrderBy(x => random.Next()).ToArray());
        }

        private string? FindUserDn(LdapConnection connection, string email)
        {
            var request = new SearchRequest(
                _ldapSettings.BaseDn,
                $"(|(mail={Escape(email)})(userPrincipalName={Escape(email)}))",
                SearchScope.Subtree,
                "distinguishedName"
            );

            var response = (SearchResponse)connection.SendRequest(request);
            return response.Entries.Cast<SearchResultEntry>()
                .FirstOrDefault()
                ?.DistinguishedName;
        }

        private static string Escape(string value)
        {
            return value
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }

        private bool UserExistsBySamAsync(LdapConnection connection, string samAccountName)
        {
            var request = new SearchRequest(
                _ldapSettings.BaseDn,
                $"(sAMAccountName={samAccountName})",
                SearchScope.Subtree,
                "sAMAccountName"
            );
            var response = (SearchResponse)connection.SendRequest(request);
            return response.Entries.Count > 0;
        }
        public string GenerateSamAccountName(string fullName)
        {
            var baseName = fullName.Replace(" ", "").ToLower();
            var samAccountName = baseName;
            int suffix = 1;
            while (true)
            {
                var existingUser = GetByUsernameAsync(
                    _ldapAuthenticator.BindAsServiceAccount(),
                    samAccountName
                ).Result;
                if (existingUser == null)
                {
                    return samAccountName;
                }
                samAccountName = $"{baseName}{suffix}";
                suffix++;
            }
        }

        private void SetPassword(LdapConnection connection, string userDn, string password)
        {
            var pwdBytes = Encoding.Unicode.GetBytes($"\"{password}\"");
            var mod = new DirectoryAttributeModification
            {
                Name = "unicodePwd",
                Operation = DirectoryAttributeOperation.Replace
            };
            mod.Add(pwdBytes);
            connection.SendRequest(new ModifyRequest(userDn, mod));
        }

        private string GetDepartmentOuDnAsync(LdapConnection connection, string department)
        {
            var request = new SearchRequest(
                _ldapSettings.BaseDn,
                $"(&(objectClass=organizationalUnit)(ou={department}))",
                SearchScope.Subtree,
                "distinguishedName"
            );

            var response = (SearchResponse)connection.SendRequest(request);
            var ouEntry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
            if (ouEntry == null) throw new InvalidOperationException("Department OU does not exist.");
            return ouEntry.DistinguishedName;
        }
    }
}
