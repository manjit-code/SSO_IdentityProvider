using Esyasoft.Ldap.Gateway.Infrastructure.Configuration;

namespace Esyasoft.Ldap.Gateway.API.DTOs
{
    public class UserSearchFilters
    {
        public string? Username { get; set; } = string.Empty;
        public string? DisplayName { get; set; } = string.Empty;
        public string? Email { get; set; } = string.Empty;
        public string? Department { get; set; } = string.Empty;
        public string? Title { get; set; } = string.Empty;
        public string? ManagerEmail { get; set; } = string.Empty;
        public string? AccountStatus { get; set; } = string.Empty;
        public string? Phone { get; set; } = string.Empty;
        public string? City { get; set; } = string.Empty;
        public string? State { get; set; } = string.Empty;
        public string? PostalCode { get; set; } = string.Empty;
        public string? Country { get; set; } = string.Empty;
    }
}
