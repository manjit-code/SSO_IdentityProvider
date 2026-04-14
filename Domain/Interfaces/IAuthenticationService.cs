using Esyasoft.Ldap.Gateway.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Domain.Interfaces
{
    public interface IAuthenticationService
    {
        Task<string> AuthenticateAsync(string username, string password);

        /// <summary>
        /// Returns LoginDetailedResult with one of:
        ///   "success", "wrong_password", "account_locked",
        ///   "user_not_found", "provider_error"
        /// </summary>
        Task<LoginDetailedResult> LoginDetailedAsync(string username, string password);

        /// <summary>
        /// Returns LoginDetailedResult with Result = "account_locked" or "not_locked".
        /// </summary>
        Task<LoginDetailedResult> GetLockoutStatusAsync(string username);
    }
}
