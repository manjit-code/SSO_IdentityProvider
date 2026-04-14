using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.DirectoryServices.Protocols;
using System.Text.Json.Serialization;

namespace Esyasoft.Ldap.Gateway.API.DTOs
{
    public class NewConsumerRequest
    {
        public string FullName { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;

        // ── LDAP-mapped ────────────────────────────────
        public string Title { get; set; } = string.Empty;
        public string TelephoneNumber { get; set; } = string.Empty;
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