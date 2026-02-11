using Microsoft.Extensions.Options;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System.DirectoryServices.Protocols;
using System.Net;

namespace SSO_IdentityProvider.Infrastructure.Ldap
{
    public class LdapAuthenticationService : ILdapAuthenticator
    {
        private readonly LdapSettings _ldapSettings;
        private readonly LdapInfraSettings _ldapInfraSettings;
        public LdapAuthenticationService(IOptions<LdapSettings> options, IOptions<LdapInfraSettings> opt)
        {
            _ldapSettings = options.Value;
            _ldapInfraSettings = opt.Value;
        }

        // Universal bind method for both OpenLDAP and AD
        private LdapConnection BindToLdap(string host, int port, bool useSsl, string bindDn, string password)
        {
            var identifier = new LdapDirectoryIdentifier(host, port, useSsl, false);
            var connection = new LdapConnection(identifier)
            {
                AuthType = AuthType.Basic,
                Credential = new NetworkCredential(bindDn, password)
            };

            // Set protocol version based on LDAP type
            connection.SessionOptions.ProtocolVersion = 3; // Both OpenLDAP and AD support LDAPv3

            if (useSsl)
            {
                connection.SessionOptions.SecureSocketLayer = true;
                // For AD with self-signed certificates, you might need to accept all
                connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;
            }

            try
            {
                connection.Bind();
                return connection;
            }
            catch (LdapException ex)
            {
                Console.WriteLine($"LDAP Bind failed for {bindDn}: {ex.Message} (Error: {ex.ErrorCode})");

                // AD-specific error handling
                if (_ldapSettings.LdapType == LdapType.ActiveDirectory)
                {
                    Console.WriteLine($"AD Connection Details: Host={host}, Port={port}, UseSsl={useSsl}");
                    Console.WriteLine($"Service Account: {bindDn}");

                    // Common AD errors
                    if (ex.ErrorCode == 81) // Server unreachable
                    {
                        throw new Exception($"AD server unreachable at {host}:{port}. Check network/firewall.");
                    }
                    else if (ex.ErrorCode == 49) // Invalid credentials
                    {
                        throw new Exception($"Invalid AD service account credentials for {bindDn}");
                    }
                }

                throw;
            }
        }

        // Helper method to bind to OpenLDAP
        private LdapConnection BindToOpenLdap(string host, int port, bool useSsl, string bindDn, string password)
        {
            var identifier = new LdapDirectoryIdentifier(host, port, useSsl, false);
            var connection = new LdapConnection(identifier)
            {
                AuthType = AuthType.Basic,
                Credential = new NetworkCredential(bindDn, password)
            };
            connection.SessionOptions.ProtocolVersion = 3;
            if (useSsl)
            {
                connection.SessionOptions.SecureSocketLayer = true;
                connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;
            }
            try
            {
                connection.Bind();
                return connection;
            }
            catch (LdapException ex)
            {
                Console.WriteLine($"LDAP Bind failed for {bindDn}: {ex.Message}");
                throw;
            }
        }
        public LdapConnection BindAsServiceAccount()
        {
            return BindToLdap(
                _ldapSettings.Host,
                _ldapSettings.Port,
                _ldapSettings.UseSsl,
                _ldapSettings.username,
                _ldapSettings.password
            );
        }


        public async Task<LdapConnection?> BindAsUserAsync(string username, string password)
        {

            return await Task.Run(() =>
            {
                try
                {
                    // First, bind as service account to search for user
                    using var searchConnection = BindAsServiceAccount();
                    string searchFilter;
                    if (username.Contains("@")) // email
                    {
                        searchFilter = _ldapSettings.LdapType == LdapType.ActiveDirectory
                            ? $"(userPrincipalName={username})"
                            : $"(mail={username})";
                    }
                    else
                    {
                        searchFilter = _ldapSettings.LdapType == LdapType.ActiveDirectory
                            ? $"(sAMAccountName={username})"
                            : $"(uid={username})";
                    }

                    var searchRequest = new SearchRequest(
                        _ldapSettings.BaseDn,
                        searchFilter,
                        SearchScope.Subtree,
                        "dn"
                    );
                    var response = (SearchResponse)searchConnection.SendRequest(searchRequest);
                    var userEntry = response.Entries.Cast<SearchResultEntry>().FirstOrDefault();

                    if (userEntry == null)
                    {
                        Console.WriteLine($"User not found: {username}");
                        return null;
                    }

                    var userDn = userEntry.DistinguishedName;

                    // Bind with user credentials
                    var identifier = new LdapDirectoryIdentifier(
                        _ldapSettings.Host,
                        _ldapSettings.Port,
                        _ldapSettings.UseSsl,
                        false
                    );

                    var connection = new LdapConnection(identifier)
                    {
                        AuthType = AuthType.Basic,
                        Credential = new NetworkCredential(userDn, password)
                    };
                    if (_ldapSettings.LdapType == LdapType.OpenLDAP)
                    {
                        connection.SessionOptions.ProtocolVersion = 3;
                    }

                    if (_ldapSettings.UseSsl)
                    {
                        connection.SessionOptions.SecureSocketLayer = true;
                        connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;
                    }

                    connection.Bind();
                    return connection;
                }
                catch (LdapException ldapEx) when (ldapEx.ErrorCode == 49)
                {
                    Console.WriteLine($"LDAP Bind Error: {ldapEx.ErrorCode} - {ldapEx.Message}");

                    // Check for ppolicy specific errors
                    if (ldapEx.Message.Contains("Constraint violation", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new UnauthorizedAccessException("Password does not meet policy requirements.");
                    }
                    else if (ldapEx.Message.Contains("password expired", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new UnauthorizedAccessException("Password expired. Please reset your password.");
                    }
                    else if (ldapEx.Message.Contains("account locked", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new UnauthorizedAccessException("Account locked due to too many failed attempts. Try again in 5 minutes.");
                    }

                    return null;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"General Bind Error: {ex.Message}");
                    throw new UnauthorizedAccessException("Authentication failed. Please try again.");
                }
            });
        }

        public LdapConnection BindAsServiceAccountForWrite()
        {
            return BindAsServiceAccount();
        }

        public LdapConnection BindAsInfraServiceAccountForWrite()
        {
            return BindToLdap(
                _ldapInfraSettings.Host,
                _ldapInfraSettings.Port,
                _ldapInfraSettings.UseSsl,
                _ldapInfraSettings.Username,
                _ldapInfraSettings.Password
            );
        }
    }
}