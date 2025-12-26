using Microsoft.Extensions.Options;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System.DirectoryServices.Protocols;

namespace SSO_IdentityProvider.Infrastructure.Ldap
{
    public class LdapAuthenticationService : ILdapAuthenticator
    {
        private readonly LdapSettings _ldapSettings;

        public LdapAuthenticationService(IOptions<LdapSettings> options)
        {
            _ldapSettings = options.Value;
        }
        public async Task<LdapConnection> BindAsUserAsync(string username, string password)
        {

            return await Task.Run(() =>
            {
                var identifier = new LdapDirectoryIdentifier(
                    _ldapSettings.Host, 
                    _ldapSettings.Port
                );

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

                if(_ldapSettings.UseSsl)
                {
                    connection.SessionOptions.SecureSocketLayer = true;
                }

                // tells to use LDAPv3 protocol TO connect to the Domain Controller(VM Server)
                connection.SessionOptions.ProtocolVersion = 3;


                Console.WriteLine("Attempting to bind to LDAP server...");
                Console.WriteLine($"Host: {_ldapSettings.Host}, Port: {_ldapSettings.Port}, User: {username}");
                Console.WriteLine(connection);
                connection.Bind();

                return connection;
            });
        }
    }
}
