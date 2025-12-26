using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SSO_IdentityProvider.Domain.Interfaces
{
    public interface IAuthenticationService
    {
        Task<string> AuthenticateAsync(string username, string password);
    }
}
