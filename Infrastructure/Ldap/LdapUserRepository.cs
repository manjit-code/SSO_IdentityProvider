using Microsoft.Extensions.Options;
using SSO_IdentityProvider.Domain.Entities;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

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

                var searchFilter = username.EndsWith("@corp.local", StringComparison.OrdinalIgnoreCase)
                                    ? $"(mail={username})"
                                    : $"(uid={username})";

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    searchFilter,
                    SearchScope.Subtree,
                    "cn", "mail", "uid", "dn"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                var entry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                if (entry == null)
                {
                    return null;
                }

                var newUser = new User
                {
                    UserName = entry.Attributes["uid"]?[0]?.ToString() ?? username,
                    DistinguishedName = entry.DistinguishedName
                };

                return newUser;
            });
        }

        public async Task<DirectoryUser?> GetMyProfileAsync(LdapConnection connection, string username)
        {
            return await Task.Run(() =>
            {
                var searchFilter = username.EndsWith("@corp.local", StringComparison.OrdinalIgnoreCase)
                                    ? $"(mail={username})"
                                    : $"(uid={username})";

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    searchFilter,
                    SearchScope.Subtree,
                    "distinguishedName",
                    "cn",
                    "mail",
                    "telephoneNumber",
                    "description",
                    "title",
                    "memberOf",
                    "manager",
                     _ldapSettings.AccountStatusAttribute
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
                        .Select(dn => dn.Split(',')[0].Replace("cn=", ""))
                        .ToList();
                }

                var description = entry.Attributes["description"]?[0]?.ToString();
                var descriptionAttributes = ParseDescriptionAttributes(description);

                string? department = null;
                if (descriptionAttributes.TryGetValue("Department", out var deptValue))
                {
                    department = deptValue;
                }

                // Check account status: Multiple Possible Keys Checks
                bool isEnabled = true;
                if (descriptionAttributes.TryGetValue("Account Status", out var statusValue))
                {
                    isEnabled = !statusValue.Contains("Disabled", StringComparison.OrdinalIgnoreCase);
                }
                else if (descriptionAttributes.TryGetValue("Status", out var altStatusValue))
                {
                    isEnabled = !altStatusValue.Contains("Disabled", StringComparison.OrdinalIgnoreCase);
                }

                return new DirectoryUser
                {
                    Username = username.Contains("@") ? username.Split('@')[0] : username,
                    DistinguishedName = entry.DistinguishedName,
                    DisplayName = entry.Attributes["cn"]?[0]?.ToString(),
                    Email = entry.Attributes["mail"]?[0]?.ToString(),
                    Phone = entry.Attributes["telephoneNumber"]?[0]?.ToString(),
                    Department =department,
                    Title = entry.Attributes["title"]?[0]?.ToString(),
                    Manager = entry.Attributes["manager"]?[0]?.ToString(),
                    Groups = groups,
                    IsEnabled = isEnabled
                };
            });
        }

        private Dictionary<string, string> ParseDescriptionAttributes(string? description)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrWhiteSpace(description)) return result;

            // Split by semicolon and process each part
            var parts = description.Split(';', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmedPart = part.Trim();
                var colonIndex = trimmedPart.IndexOf(':');

                if (colonIndex > 0)
                {
                    var key = trimmedPart.Substring(0, colonIndex).Trim();
                    var value = trimmedPart.Substring(colonIndex + 1).Trim();

                    if (!string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(value))
                    {
                        result[key] = value;
                    }
                }
            }

            return result;
        }
        
        public async Task<IReadOnlyCollection<DirectorySearchResult>> SearchUsersAsync(LdapConnection connection, UserSearchCriteria reqBody)
        {
            return await Task.Run(() =>
            {
                // Transform AD-specific filters to OpenLDAP
                var transformedFilters = new Dictionary<string, string>();

                if (reqBody.Filters != null)
                {
                    foreach (var (attribute, rawValue) in reqBody.Filters)
                    {
                        var openLdapAttribute = attribute switch
                        {
                            "sAMAccountName" => "uid",
                            "userPrincipalName" => "mail",
                            "displayName" => "cn",
                            _ => attribute
                        };
                        transformedFilters[openLdapAttribute] = rawValue;
                    }
                }

                // 1️⃣ Build LDAP filter
                var filterParts = new List<string>();

                foreach (var (attribute, rawValue) in transformedFilters)
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
                    0 => "(objectClass=inetOrgPerson)",
                    1 => filterParts[0],
                    _ => $"(&{string.Join("", filterParts)})"
                };


                // Transform AD-specific attributes to OpenLDAP
                var transformedAttributes = reqBody.Attributes
                    .Select(attr => attr switch
                    {
                        "sAMAccountName" => "uid",
                        "userPrincipalName" => "mail",
                        "displayName" => "cn",
                        _ => attr
                    })
                    .ToArray();

                // 2️⃣ LDAP search request
                var request = new SearchRequest(
                    reqBody.BaseDn!,
                    ldapFilter,
                    reqBody.Scope,
                    transformedAttributes
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
                        Username = entry.Attributes["uid"]?[0]?.ToString()
                           ?? entry.Attributes["cn"]?[0]?.ToString()
                           ?? "Unavailable"
                    };

                    foreach (var attr in reqBody.Attributes)
                    {

                        // Map attribute name for lookup
                        var lookupAttr = attr switch
                        {
                            "sAMAccountName" => "uid",
                            "userPrincipalName" => "mail",
                            "displayName" => "cn",
                            _ => attr
                        };

                        if (!entry.Attributes.Contains(lookupAttr)) continue;

                        var value = entry.Attributes[lookupAttr]?[0]?.ToString();
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
            return await Task.Run(() => {

                // Change from sAMAccountName to uid search
                var searchFilter = $"(uid={username})";
                if (username.Contains("@"))
                {
                    searchFilter = $"(mail={username})";
                }

                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    searchFilter,
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
                    .Select(dn => dn.Split(',')[0].Replace("cn=", "")) // Extract CN from DN
                    .ToList();

                return groups;
            });
        }

        public async Task UpdateUserProfileAsync(string userDn, UpdateMyProfile profile)
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


                // For OpenLDAP, use 'cn' instead of 'displayName'
                // or add both for consistency
                if (!string.IsNullOrWhiteSpace(profile.DisplayName))
                {
                    // Option 1: Update cn (recommended for OpenLDAP)
                    var cnMod = new DirectoryAttributeModification
                    {
                        Name = "cn",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    cnMod.Add(profile.DisplayName);
                    modifications.Add(cnMod);

                    // Option 2: Also update displayName if your schema supports it
                    var displayNameMod = new DirectoryAttributeModification
                    {
                        Name = "displayName",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    displayNameMod.Add(profile.DisplayName);
                    modifications.Add(displayNameMod);
                }

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
                    // Validate password policy
                    ValidatePasswordPolicy(profile.NewPassword);

                    // Change password
                    ChangePassword(connection, userDn, profile.NewPassword);
                }

            });
        }

        private static void ChangePassword(LdapConnection connection, string userDn, string newPassword)
        {
            try
            {
                var hashedPassword = GenerateSSHAHash(newPassword);

                var mod = new DirectoryAttributeModification
                {
                    Name = "userPassword",
                    Operation = DirectoryAttributeOperation.Replace
                };
                mod.Add(hashedPassword);

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
            catch (LdapException ex) when (ex.ErrorCode == 53) // LDAP_UNWILLING_TO_PERFORM
            {
                throw new InvalidOperationException(
                    "Password does not meet policy requirements (length, complexity, history).",
                    ex
                );
            }
        }


        public async Task<CreateUserResponse> CreateUserAsync(CreateUserCommand newUser)
        {
            var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

            // Generate uid (OpenLDAP equivalent of sAMAccountName)
            var uid = GenerateUid(newUser.FullName);

            // Check if user exists by uid
            if (UserExistsByUid(connection, uid))
            {
                throw new InvalidOperationException("User already exists.");
            }

            // Check if department OU exists
            var departmentOuDn = $"ou={newUser.Department},ou=Employees,dc=corp,dc=local";
            if(!DepartmentOuExists(connection, departmentOuDn))
            {
                throw new InvalidOperationException($"Department OU '{newUser.Department}' does not exist.");
            }

            string? managerDn = null;
            if (!string.IsNullOrWhiteSpace(newUser.ManagerEmail))
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
            var uidNumber = GetNextUidNumber(connection);
            var email = $"{uid}@corp.local";
            var userDn = $"uid={uid},{departmentOuDn}";
            var password = GenerateStrongPassword();
            var hashedPassword = GenerateSSHAHash(password);

            if (managerDn != null && managerDn.Equals(userDn, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "A user cannot be their own manager."
                );
            }

            // Create user ->
            var nameParts = newUser.FullName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var attributes = new List<DirectoryAttribute> { 
                new DirectoryAttribute("objectClass", new[] { "top", "person", "organizationalPerson", "inetOrgPerson"}),
                new DirectoryAttribute("cn", newUser.FullName),
                //new DirectoryAttribute("givenName", nameParts[0]),
                new DirectoryAttribute("sn",  nameParts.Length > 1 ? nameParts[^1] : nameParts[0]),
                new DirectoryAttribute("uid", uid),
                new DirectoryAttribute("userPassword", hashedPassword),
                new DirectoryAttribute("mail", email),
                //new DirectoryAttribute("department", newUser.Department), // this attribute is not in OpenLdap
                new DirectoryAttribute("description", $"Department: {newUser.Department}"),
                new DirectoryAttribute("title", newUser.Title),
                new DirectoryAttribute("telephoneNumber", newUser.TelephoneNumber),
                //new DirectoryAttribute("userAccountControl", "514") // disabled account
            };

            if (managerDn != null)
            {
                attributes.Add(
                    new DirectoryAttribute("manager", managerDn)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.StreetAddress))
            {
                attributes.Add(
                    new DirectoryAttribute("streetAddress", newUser.StreetAddress)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.City))
            {
                attributes.Add(
                    new DirectoryAttribute("l", newUser.City)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.State))
            {
                attributes.Add(
                    new DirectoryAttribute("st", newUser.State)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.PostalCode))
            {
                attributes.Add(
                    new DirectoryAttribute("postalCode", newUser.PostalCode)
                );
            }
            if (!string.IsNullOrWhiteSpace(newUser.Country))
            {
                if (newUser.Country.Length != 2)
                    throw new InvalidOperationException(
                        "Country must be a 2-letter ISO code (e.g., IN, US)."
                    );

                attributes.Add(new DirectoryAttribute("c", newUser.Country.ToUpper()));
            }

            try
            {
                var addRequest = new AddRequest(userDn, attributes.ToArray());
                connection.SendRequest(addRequest);
            }
            catch(DirectoryOperationException ex)
            {
                Console.WriteLine($"First attempt failed: {ex.Message}");
                Console.WriteLine("Trying with minimal attributes...");

                var minimalAttributes = new List<DirectoryAttribute>
                {
                    new DirectoryAttribute("objectClass", new[] { "top", "person", "organizationalPerson", "inetOrgPerson" }),
                    new DirectoryAttribute("cn", newUser.FullName),
                    new DirectoryAttribute("sn", nameParts.Length > 1 ? nameParts[^1] : nameParts[0]),
                    new DirectoryAttribute("uid", uid),
                    new DirectoryAttribute("userPassword", hashedPassword),
                    new DirectoryAttribute("mail", email)
                };

                var retryRequest = new AddRequest(userDn, minimalAttributes.ToArray());
                connection.SendRequest(retryRequest);

                await Task.Delay(100);
                UpdateUserAttributes(connection, userDn, newUser, managerDn);
            }
            

            // Set password
            //SetPassword(connection, userDn, password);

            //// Enable account + password never expires
            //var modifications = new DirectoryAttributeModification
            //{
            //    Name = "userAccountControl",
            //    Operation = DirectoryAttributeOperation.Replace
            //};
            //modifications.Add("66048"); // Enabled + Password never expires
            //connection.SendRequest(new ModifyRequest(userDn, modifications));

            return new CreateUserResponse
            {
                Username = uid,
                InitialPassword = password,
                Email = email,
                DistinguishedName = userDn
            };
        }

       //-------------------------------------------------------------------------
        private bool UserExistsByUid(LdapConnection connection, string uid)
        {
            var request = new SearchRequest(
                _ldapSettings.BaseDn,
                $"(uid={uid})",
                SearchScope.Subtree,
                "uid"
            );
            var response = (SearchResponse)connection.SendRequest(request);
            return response.Entries.Count > 0;
        }

        private bool DepartmentOuExists(LdapConnection connection, string ouDn)
        {
            try
            {
                var request = new SearchRequest(
                    ouDn,
                    "(objectClass=organizationalUnit)",
                    SearchScope.Base,
                    "ou"
                );
                var response = (SearchResponse)connection.SendRequest(request);
                return response.Entries.Count > 0;
            }
            catch
            {
                return false;
            }
        }
        private string GenerateUid(string fullName)
        {
            var baseUid = fullName.ToLower()
                .Replace(" ", ".")
                .Replace("'", "")
                .Replace(",", "");

            var uid = baseUid;
            int suffix = 1;

            while (UserExistsByUid(_ldapAuthenticator.BindAsServiceAccount(), uid))
            {
                uid = $"{baseUid}{suffix}";
                suffix++;
            }

            return uid;
        }

        private void UpdateUserAttributes(LdapConnection connection, string userDn, CreateUserCommand newUser, string? managerDn)
        {
            var modifications = new List<DirectoryAttributeModification>();

            if (!string.IsNullOrWhiteSpace(newUser.Department))
            {
                var descMod = new DirectoryAttributeModification
                {
                    Name = "description",
                    Operation = DirectoryAttributeOperation.Add
                };
                descMod.Add($"Department: {newUser.Department}");
                modifications.Add(descMod);
            }


            if (!string.IsNullOrWhiteSpace(newUser.Title))
            {
                var mod = new DirectoryAttributeModification
                {
                    Name = "title",
                    Operation = DirectoryAttributeOperation.Add
                };
                mod.Add(newUser.Title);
                modifications.Add(mod);
            }

            if (!string.IsNullOrWhiteSpace(newUser.TelephoneNumber))
            {
                var mod = new DirectoryAttributeModification
                {
                    Name = "telephoneNumber",
                    Operation = DirectoryAttributeOperation.Add
                };
                mod.Add(newUser.TelephoneNumber);
                modifications.Add(mod);
            }

            if (managerDn != null)
            {
                var mod = new DirectoryAttributeModification
                {
                    Name = "manager",
                    Operation = DirectoryAttributeOperation.Add
                };
                mod.Add(managerDn);
                modifications.Add(mod);
            }

            if (modifications.Count > 0)
            {
                var modifyRequest = new ModifyRequest(userDn, modifications.ToArray());
                connection.SendRequest(modifyRequest);
            }
        }

        private int GetNextUidNumber(LdapConnection connection)
        {
            // Find the highest existing uidNumber
            var request = new SearchRequest(
                _ldapSettings.BaseDn,
                "(uidNumber=*)",
                SearchScope.Subtree,
                "uidNumber"
            );

            var response = (SearchResponse)connection.SendRequest(request);
            var maxUidNumber = 10000; // Start from 10000

            foreach (SearchResultEntry entry in response.Entries)
            {
                if (entry.Attributes.Contains("uidNumber"))
                {
                    var uidNumberStr = entry.Attributes["uidNumber"][0].ToString();
                    if (int.TryParse(uidNumberStr, out var uidNumber))
                    {
                        maxUidNumber = Math.Max(maxUidNumber, uidNumber);
                    }
                }
            }

            return maxUidNumber + 1;
        }
        private bool ValidatePasswordPolicy(string password)
        {
            //// Minimum length
            //if (password.Length < 8)
            //    throw new InvalidOperationException("Password must be at least 8 characters long.");

            //// Complexity requirements
            //var hasUpper = password.Any(char.IsUpper);
            //var hasLower = password.Any(char.IsLower);
            //var hasDigit = password.Any(char.IsDigit);
            //var hasSpecial = password.Any(ch => !char.IsLetterOrDigit(ch));

            //var complexityScore = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) +
            //                     (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);

            //if (complexityScore < 3)
            //    throw new InvalidOperationException(
            //        "Password must contain at least 3 of: uppercase, lowercase, digits, special characters.");

            //return true;


            if (password.Length < 8)
            {
                throw new InvalidOperationException("Password must be at least 8 characters long.");
            }

            return true;
        }

        private static string GenerateSSHAHash(string password)
        {
            using (var sha = System.Security.Cryptography.SHA1.Create())
            {
                // Generate random salt (4-8 bytes typical)
                var salt = new byte[4];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                {
                    rng.GetBytes(salt);
                }

                // Combine password and salt
                var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
                var saltedPassword = new byte[passwordBytes.Length + salt.Length];
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, 0, passwordBytes.Length);
                Buffer.BlockCopy(salt, 0, saltedPassword, passwordBytes.Length, salt.Length);

                // Compute hash
                var hash = sha.ComputeHash(saltedPassword);

                // Combine hash and salt for SSHA format
                var hashWithSalt = new byte[hash.Length + salt.Length];
                Buffer.BlockCopy(hash, 0, hashWithSalt, 0, hash.Length);
                Buffer.BlockCopy(salt, 0, hashWithSalt, hash.Length, salt.Length);

                return "{SSHA}" + Convert.ToBase64String(hashWithSalt);
            }
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
                $"(mail={Escape(email)})",
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
            //var pwdBytes = Encoding.Unicode.GetBytes($"\"{password}\"");
            var hashedPassword = GenerateSSHAHash(password);
            var mod = new DirectoryAttributeModification
            {
                Name = "userPassword",
                Operation = DirectoryAttributeOperation.Replace
            };
            mod.Add(hashedPassword);
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

        public async Task UpdateUserAsAdminAsync(AdminUpdateUserCommand command)
        {
            await Task.Run(() =>
            {
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

                // 1️. Resolve user DN
                var userDn = FindUserDnByEmail(connection, command.Email) ?? throw new InvalidOperationException($"Target user with email '{command.Email}' not found.");


                // V.IMP : Get current descriotion to preserve other unchanged information
                string currentDescription = "";
                try
                {
                    var searchRequest = new SearchRequest(
                            userDn,
                            "(objectClass=inetOrgPerson)",
                            SearchScope.Base,
                            "description"
                    );

                    var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                    var entry = searchResponse.Entries.Cast<SearchResultEntry>().FirstOrDefault();
                    if (entry != null && entry.Attributes.Contains("description"))
                    {
                        currentDescription = entry.Attributes["description"][0]?.ToString() ?? "";
                    }
                }
                catch
                {
                    throw new InvalidOperationException("Existing Description Not Found.");
                }

                // Parse current description attributes
                var descriptionAttributes = ParseDescriptionAttributes(currentDescription);


                // 2️. Handle department change: OU move
                string? newUserDn = null;
                if (!string.IsNullOrWhiteSpace(command.Department))
                {
                    var targetOuDn = GetDepartmentOuDnAsync(connection, command.Department);
                    MoveUserToOu(connection, userDn, targetOuDn);

                    // After move, DN changes: recompute
                    var uid = ExtractUidFromDn(userDn);
                    newUserDn = $"uid={uid},{targetOuDn}";

                    // Update department in description attributes
                    descriptionAttributes["Department"] = command.Department;
                }
                // Use new DN if user was moved
                var effectiveUserDn = newUserDn ?? userDn;
                var modifications = new List<DirectoryAttributeModification>();

                // Update description with both department and preserved account status
                if (!string.IsNullOrWhiteSpace(command.Department) || !string.IsNullOrWhiteSpace(currentDescription))
                {
                    var newDescriptionParts = new List<string>();

                    string department = !string.IsNullOrWhiteSpace(command.Department)
                        ? command.Department
                        : (descriptionAttributes.TryGetValue("Department", out var existingDept) ? existingDept : "");

                    if (!string.IsNullOrWhiteSpace(department))
                    {
                        newDescriptionParts.Add($"Department: {department}");
                    }

                    // Preserve account status if exists
                    if (descriptionAttributes.TryGetValue("Account Status", out var accountStatus))
                    {
                        newDescriptionParts.Add($"Account Status: {accountStatus}");
                    }
                    else if (descriptionAttributes.TryGetValue("Status", out var altStatus))
                    {
                        newDescriptionParts.Add($"Account Status: {altStatus}");
                    }
                    else
                    {
                        // Default to Active if no status found
                        newDescriptionParts.Add("Account Status: Active");
                    }

                    string newDescription = string.Join("; ", newDescriptionParts);

                    // Also update description for compatibility
                    var descMod = new DirectoryAttributeModification
                    {
                        Name = "description",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    descMod.Add(newDescription);
                    modifications.Add(descMod);
                }

                if (!string.IsNullOrWhiteSpace(command.Title))
                {
                    var mod = new DirectoryAttributeModification
                    {
                        Name = "title",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    mod.Add(command.Title);
                    modifications.Add(mod);
                }

                // 3️. Manager assignment
                if (!string.IsNullOrWhiteSpace(command.ManagerEmail))
                {
                    var managerDn = FindUserDnByEmail(connection, command.ManagerEmail)
                        ?? throw new InvalidOperationException("Manager not found.");

                    if (string.Equals(managerDn, effectiveUserDn, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("User cannot be their own manager.");

                    var mod = new DirectoryAttributeModification
                    {
                        Name = "manager",
                        Operation = DirectoryAttributeOperation.Replace
                    };
                    mod.Add(managerDn);
                    modifications.Add(mod);
                }
                

                if (modifications.Any())
                {
                    connection.SendRequest(new ModifyRequest(effectiveUserDn, modifications.ToArray()));
                }
            });
        }

        private bool IsWithinAllowedParent(string dn)
        {
            var allowedParents = new[]
            {
                "ou=Employees,dc=corp,dc=local"
            };

            var normalizedDn = dn.Trim().ToLower();

            foreach (var allowedParent in allowedParents)
            {
                var normalizedParent = allowedParent.Trim().ToLower();

                // Check if DN is exactly the allowed parent or is a child of it
                if (normalizedDn == normalizedParent ||
                    normalizedDn.EndsWith("," + normalizedParent))
                {
                    return true;
                }
            }

            return false;
        }

        private static string ExtractUidFromDn(string userDn)
        {
            var rdn = userDn.Split(',')[0];
            if (rdn.StartsWith("uid=", StringComparison.OrdinalIgnoreCase)) return rdn.Substring(4); // Remove "uid="
            if (rdn.StartsWith("cn=", StringComparison.OrdinalIgnoreCase)) return rdn.Substring(3); // Remove "cn="
            return rdn;
        }

        private string? FindUserDnByEmail(LdapConnection connection, string email)
        {
            try
            {
                var request = new SearchRequest(
                    _ldapSettings.BaseDn,
                    $"(mail={Escape(email)})",
                    SearchScope.Subtree,
                    "distinguishedName"
                );

                var response = (SearchResponse)connection.SendRequest(request);
                return response.Entries.Cast<SearchResultEntry>().FirstOrDefault()?.DistinguishedName;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error finding user by email '{email}': {ex.Message}");
                return null;
            }
        }
        private static string GetParentOuDn(string userDn)
        {
            var index = userDn.IndexOf(",");
            if (index == -1) throw new InvalidOperationException("Invalid DN format.");

            return userDn.Substring(index + 1);
        }
        private void MoveUserToOu(LdapConnection connection, string userDn, string targetOuDn)
        {
            var currentParentDn = GetParentOuDn(userDn);

            // If already in target OU → do nothing
            if (string.Equals(currentParentDn, targetOuDn, StringComparison.OrdinalIgnoreCase)) return;

            var rdn = userDn.Split(',')[0];

            var request = new ModifyDNRequest(userDn, targetOuDn, rdn)
            {
                DeleteOldRdn = true
            };

            connection.SendRequest(request);
        }

        public async Task UpdateUserStatusAsync(UpdateUserStatusCommand command)
        {
            await Task.Run(() =>
            {
                var connection = _ldapAuthenticator.BindAsServiceAccountForWrite();

                var userDn = FindUserDn(connection, command.Email)
                    ?? throw new InvalidOperationException($"User with email '{command.Email}' not found.");

                // First, get current description
                var searchRequest = new SearchRequest(
                    userDn,
                    "(objectClass=inetOrgPerson)",
                    SearchScope.Base,
                    "description"
                );
                var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);
                var entry = searchResponse.Entries.Cast<SearchResultEntry>().FirstOrDefault()
                    ?? throw new InvalidOperationException("User not found.");

                string currentDescription = "";
                if(entry != null && entry.Attributes.Contains("description"))
                {
                    currentDescription = entry.Attributes["description"][0]?.ToString() ?? "";
                }

                var descriptionAttributes = ParseDescriptionAttributes(currentDescription);

                string newDescription = BuildDescriptionString(descriptionAttributes, command.IsEnabled);

                var mod = new DirectoryAttributeModification
                {
                    Name = "description",
                    Operation = DirectoryAttributeOperation.Replace
                    //Operation = command.IsEnabled
                    //            ? DirectoryAttributeOperation.Delete  // Remove lock
                    //            : DirectoryAttributeOperation.Replace // Set lock (000001010000Z means locked)
                };
                mod.Add(newDescription);
                try
                {
                    connection.SendRequest(new ModifyRequest(userDn, mod));
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error updating user status: {ex.Message}");
                    throw;
                }
            });
        }

        private string BuildDescriptionString(Dictionary<string, string> attributes, bool isEnabled)
        {
            // Create a copy to avoid modifying the original
            var attrCopy = new Dictionary<string, string>(attributes, StringComparer.OrdinalIgnoreCase);

            attrCopy["Account Status"] = isEnabled ? "Active" : "Disabled";

            // Remove old "Status" key if present
            if (attrCopy.ContainsKey("Status"))
            {
                attrCopy.Remove("Status");
            }

            var descriptionParts = new List<string>();

            // Add prioritized attributes first
            var priorityAttributes = new[] { "Department", "Account Status" };

            foreach (var priorityKey in priorityAttributes)
            {
                if (attrCopy.TryGetValue(priorityKey, out var value))
                {
                    descriptionParts.Add($"{priorityKey}: {value}");
                    attrCopy.Remove(priorityKey);
                }
            }

            // Add remaining attributes in alphabetical order
            var remainingKeys = attrCopy.Keys.OrderBy(k => k).ToList();
            foreach (var key in remainingKeys)
            {
                descriptionParts.Add($"{key}: {attrCopy[key]}");
            }

            return string.Join("; ", descriptionParts);
        }

        public async Task CreateOuAsync(CreateOuCommand command)
        {
            await Task.Run(() =>
            {
                //var connection = _ldapAuthenticator.BindAsInfraServiceAccountForWrite();

                var connection = _ldapAuthenticator.BindAsInfraServiceAccountForWrite();
                if (string.IsNullOrWhiteSpace(command.NewOuName))
                {
                    throw new InvalidOperationException("OU name is required");
                }

                // Validate OU name
                if (command.NewOuName.Any(c => "\\,+\"<>;=".Contains(c)))
                {
                    throw new InvalidOperationException("OU name contains invalid characters");
                }

                // Check if parent is within allowed hierarchy
                if (!IsWithinAllowedParent(command.ParentOuDn))
                {
                    throw new InvalidOperationException(
                        $"Security Violation: Parent OU must be within allowed hierarchy. " +
                        $"Allowed: ou=Employees,dc=corp,dc=local");
                }

                // 3. Parent Existence Check: Verify the parent actually exists in AD
                var parentCheckRequest = new SearchRequest(
                    command.ParentOuDn,
                    "(objectClass=*)",
                    SearchScope.Base, // Base scope checks only the object itself
                    "distinguishedName"
                );

                try
                {
                    connection.SendRequest(parentCheckRequest);
                }
                catch (DirectoryOperationException)
                {
                    throw new InvalidOperationException($"The parent OU '{command.ParentOuDn}' does not exist.");
                }

                // Duplicate Check
                var existOuRequest = new SearchRequest(
                    command.ParentOuDn,
                    $"ou={Escape(command.NewOuName)}",
                    SearchScope.OneLevel,
                    "ou"
                );

                var existOuResponse = (SearchResponse)connection.SendRequest(existOuRequest);
                if (existOuResponse.Entries.Count > 0) throw new InvalidOperationException("OU with same name already exists");

                var ouDn = $"ou={command.NewOuName},{command.ParentOuDn}";
                var attributes = new DirectoryAttribute[]
                {
                    new DirectoryAttribute("objectClass", "organizationalUnit"),
                    new DirectoryAttribute("ou", command.NewOuName)
                };

                var addRequest = new AddRequest(ouDn, attributes);
                connection.SendRequest(addRequest);
            });
        }

        public async Task DeleteOuAsync(DeleteOuCommand command)
        {
            await Task.Run(() =>
            {
                //var connection = _ldapAuthenticator.BindAsInfraServiceAccountForWrite();
                var connection = _ldapAuthenticator.BindAsInfraServiceAccountForWrite();
                
                // Check if trying to delete critical OU
                var criticalOus = new[]
                {
                    "ou=Employees,dc=corp,dc=local",
                    "dc=corp,dc=local"
                };
                var normalizedOuDn = command.OuDn.Trim().ToLower();
                foreach (var criticalOu in criticalOus)
                {
                    if (normalizedOuDn == criticalOu.ToLower())
                    {
                        throw new InvalidOperationException(
                            $"Cannot delete critical organizational unit: {criticalOu}");
                    }
                }

                // Check for child objects
                var childRequest = new SearchRequest(
                    command.OuDn,
                    "(objectClass=*)",
                    SearchScope.OneLevel,
                    "distinguishedName"
                );
                var childResponse = (SearchResponse)connection.SendRequest(childRequest);

                if (childResponse.Entries.Count > 0 && !command.CascadeDelete)
                {
                    throw new InvalidOperationException(
                        "OU contains child objects. Enable CascadeDelete to proceed."
                    );
                }

                if (command.CascadeDelete)
                {
                    DeleteChildrenRecursively(connection, command.OuDn);
                }

                // Delete the OU itself
                connection.SendRequest(new DeleteRequest(command.OuDn));
            });
        }
        private void DeleteChildrenRecursively(LdapConnection connection, string parentDn)
        {
            var searchRequest = new SearchRequest(
                parentDn,
                "(objectClass=*)",
                SearchScope.OneLevel,
                "distinguishedName", "objectClass"
            );

            var response = (SearchResponse)connection.SendRequest(searchRequest);

            // Count objects by type for logging
            int userCount = 0, ouCount = 0, otherCount = 0;

            foreach (SearchResultEntry entry in response.Entries)
            {
                if (entry.Attributes.Contains("objectClass"))
                {
                    var objectClasses = entry.Attributes["objectClass"].GetValues(typeof(string))
                        .Cast<string>().Select(s => s.ToLower()).ToList();

                    if (objectClasses.Contains("organizationalunit"))
                        ouCount++;
                    else if (objectClasses.Contains("inetorgperson") || objectClasses.Contains("person"))
                        userCount++;
                    else
                        otherCount++;
                }
                else
                {
                    otherCount++;
                }

                DeleteChildrenRecursively(connection, entry.DistinguishedName);

                connection.SendRequest(new DeleteRequest(entry.DistinguishedName));
            }

            if (response.Entries.Count > 0)
            {
                Console.WriteLine($"Deleted from {parentDn}: {userCount} users, {ouCount} OUs, {otherCount} other objects");
            }
        }

    }
}
