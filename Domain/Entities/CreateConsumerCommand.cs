using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Entities
{
    public class CreateConsumerCommand
    {
        public string FullName { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;

        // ── LDAP-mapped fields ────────────────────────────────────────
        // These go into OpenLDAP AND m_employee
        public string Title { get; set; } = string.Empty;           // LDAP: title, m_employee: em_designation
        public string TelephoneNumber { get; set; } = string.Empty; // LDAP: telephoneNumber, m_employee: em_mobile
        public string? ManagerEmail { get; set; }                   // LDAP: manager (DN), m_employee: em_reporting_to
        public string? City { get; set; }                           // LDAP: l, m_employee: em_city
        public string? State { get; set; }                          // LDAP: st, m_employee: em_state
        public string? PostalCode { get; set; }                     // LDAP: postalCode, m_employee: em_pincode (parsed to int)
        public string? Country { get; set; }                        // LDAP: c (2-letter ISO)
        public string? StreetAddress { get; set; }                  // LDAP: streetAddress, m_employee: em_address1

        // ── m_employee-only fields ────────────────────────────────────
        // NOT stored in OpenLDAP — internal business fields only
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