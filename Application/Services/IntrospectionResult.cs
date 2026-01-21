using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;

namespace SSO_IdentityProvider.Application.Services
{
    public class IntrospectionResult
    {
        public bool Active { get; private set; }
        public JwtSecurityToken? Token { get; private set; }

        private IntrospectionResult(bool active, JwtSecurityToken? token = null)
        {
            Active = active;
            Token = token;
        }

        // ✅ Factory methods (RENAMED)
        public static IntrospectionResult Inactive()
            => new(false);

        public static IntrospectionResult ActiveToken(JwtSecurityToken token)
            => new(true, token);
    }


}
