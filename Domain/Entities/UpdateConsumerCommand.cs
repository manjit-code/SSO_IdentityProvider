using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Entities
{
    public class UpdateConsumerCommand
    {
        public string Username { get; set; } = string.Empty;

        // ── LDAP-mapped fields ────────────────────────────────────────
        public string? DisplayName { get; set; }     // LDAP: cn
        public string? Email { get; set; }            // LDAP: mail, AspNetUsers: Email, m_employee: em_emailid
        public string? Title { get; set; }            // LDAP: title, m_employee: em_designation
        public string? TelephoneNumber { get; set; } // LDAP: telephoneNumber, m_employee: em_mobile
        public string? Department { get; set; }       // LDAP: description (Department: X), m_employee: em_department
        public string? ManagerEmail { get; set; }    // LDAP: manager (resolved to DN), m_employee: em_reporting_to
        public string? City { get; set; }            // LDAP: l, m_employee: em_city
        public string? State { get; set; }           // LDAP: st, m_employee: em_state
        public string? PostalCode { get; set; }      // LDAP: postalCode, m_employee: em_pincode
        public string? Country { get; set; }         // LDAP: c
        public string? StreetAddress { get; set; }   // LDAP: streetAddress, m_employee: em_address1

        // ── m_employee-only fields ────────────────────────────────────

        public string? Address2 { get; set; }
        public string? Address3 { get; set; }
        public char? Gender { get; set; }
        public string? EmployeeType { get; set; }
        public string? Branch { get; set; }
        public int? OrgId { get; set; }
        public string? Remark { get; set; }

        // ── Audit ─────────────────────────────────────────────────────
        public string? ModifiedBy { get; set; }
    }
}
