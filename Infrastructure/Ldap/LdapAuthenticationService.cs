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

        public LdapConnection BindAsServiceAccount()
        {
            //Console.WriteLine($"{_ldapSettings.Host} : {_ldapSettings.Port} : {_ldapSettings.username} : {_ldapSettings.password} : {_ldapSettings.Domain}");
            var identifier = new LdapDirectoryIdentifier(
                    _ldapSettings.Host,
                    _ldapSettings.Port
                );

            var username = _ldapSettings.username;
            var password = _ldapSettings.password;

            // important to only use the username
            username = username.Contains("@")
            ? username.Split('@')[0]
            : username;


            var credentials = new System.Net.NetworkCredential(
                username,
                password,
                _ldapSettings.Domain
            );
            var connection = new LdapConnection(identifier)
            {
                AuthType = AuthType.Negotiate,
                Credential = credentials
            };

            if (_ldapSettings.UseSsl)
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }

            connection.SessionOptions.ProtocolVersion = 3;

            connection.Bind();

            return connection;
        }


        public async Task<LdapConnection?> BindAsUserAsync(string username, string password)
        {

            return await Task.Run(() =>
            {
                try
                {
                    var identifier = new LdapDirectoryIdentifier(
                        _ldapSettings.Host,
                        _ldapSettings.Port
                    );

                    //important to only use the username
                    username = username.Contains("@")
                    ? username.Split('@')[0]
                    : username;

                    var credentials = new System.Net.NetworkCredential(
                        username,
                        password,
                        _ldapSettings.Domain
                    );
                    var connection = new LdapConnection(identifier)
                    {
                        AuthType = AuthType.Negotiate,
                        Credential = credentials
                    };

                    if (_ldapSettings.UseSsl)
                    {
                        connection.SessionOptions.SecureSocketLayer = true;
                    }

                    // tells to use LDAPv3 protocol TO connect to the Domain Controller(VM Server)
                    connection.SessionOptions.ProtocolVersion = 3;

                    connection.Bind();
                    return connection;
                }
                catch (LdapException ldapEx) when (ldapEx.ErrorCode == 49)
                {
                    Console.WriteLine($"LDAP Bind Error: {ldapEx.ErrorCode} - {ldapEx.Message}");

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
            var identifier = new LdapDirectoryIdentifier(
                _ldapSettings.Host,
                _ldapSettings.PortS,
                _ldapSettings.UseSslS,
                false
            );

            var connection = new LdapConnection(identifier)
            {
                AuthType = AuthType.Negotiate,
                Credential = new NetworkCredential(_ldapSettings.username, _ldapSettings.password)
            };

            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = true;

            // Add this if your VM certificate isn't installed on your host machine
            connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;

            connection.Bind();
            return connection;
        }

        public LdapConnection BindAsInfraServiceAccountForWrite()
        {
            var identifier = new LdapDirectoryIdentifier(
                _ldapInfraSettings.Host,
                _ldapInfraSettings.Port,
                _ldapInfraSettings.UseSsl,
                false
            );

            var connection = new LdapConnection(identifier)
            {
                AuthType = AuthType.Negotiate,
                Credential = new NetworkCredential(_ldapInfraSettings.Username, _ldapInfraSettings.Password)
            };

            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = true;

            // Add this if your VM certificate isn't installed on your host machine
            connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;

            connection.Bind();
            return connection;
        }
    }
}