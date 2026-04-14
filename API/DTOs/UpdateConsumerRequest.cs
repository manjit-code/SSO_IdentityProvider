namespace Esyasoft.Ldap.Gateway.API.DTOs
{
    public class UpdateConsumerRequest
    {
        public string Username { get; set; } = string.Empty;

        // ── LDAP-mapped ────────────────────────────────
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public string? Title { get; set; }
        public string? TelephoneNumber { get; set; }
        public string? Department { get; set; }
        public string? ManagerEmail { get; set; }
        public string? StreetAddress { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? PostalCode { get; set; }
        public string? Country { get; set; }

        // ── m_employee only ────────────────────────────
        public string? Address2 { get; set; }
        public string? Address3 { get; set; }
        public char? Gender { get; set; }
        public string? EmployeeType { get; set; }
        public string? Branch { get; set; }
        public int? OrgId { get; set; }
        public string? Remark { get; set; }
        public string? ModifiedBy { get; set; }
    }
}
