using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Entities
{
    public class UpdateMyProfile
    {
        public string? DisplayName { get; set; }

        // There is no constraints in LDAP for telephone number or mobile format
        public string? TelephoneNumber { get; set; }
        public string? Mobile { get; set; }
        public string? StreetAddress { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? PostalCode { get; set; }
        public string? NewPassword { get; set; }
    }
}
