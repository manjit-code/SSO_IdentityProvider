using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.DirectoryServices.Protocols;
using System.Text.Json.Serialization;

namespace Esyasoft.Ldap.Gateway.API.DTOs
{
    public class NewConsumerResponse
    {
        public string Username { get; set; } = string.Empty;

        /// <summary>Plain-text initial password. Shown once only.</summary>
        public string InitialPassword { get; set; } = string.Empty;

        public string Email { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string PostgresUserId { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
    }
}