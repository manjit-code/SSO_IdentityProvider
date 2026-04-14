using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Interfaces
{
    public interface IOtpService
    {
        Task<string> GenerateAndStoreOtpAsync(string email);
        Task<bool> ValidateOtpAsync(string email, string otp);
    }

}
