using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Entities.Password
{
    public class ValidatePasswordRequest
    {
        [Required]
        [MinLength(8)]
        public string Password { get; set; } = string.Empty;
    }
}
