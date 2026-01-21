using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SSO_IdentityProvider.Domain.Entities;
using SSO_IdentityProvider.Domain.Interfaces;
using SSO_IdentityProvider.Infrastructure.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SSO_IdentityProvider.Infrastructure.Security
{
    public class JwtTokenService : ITokenService
    {
        private readonly JwtSettings _jwtSettings;

        public JwtTokenService(IOptions<JwtSettings> option)
        {
            _jwtSettings = option.Value;
        }
        public string GenerateAccessToken(User user, IEnumerable<string> roles, IReadOnlyCollection<string> scopes)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("scope", string.Join(" ", scopes))
            };

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_jwtSettings.Secret));

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1), //or minutes
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public string GenerateIdToken(User user,string clientId,string nonce,DateTime issuedAt, IReadOnlyCollection<string> scopes)
        {
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.UserName),
                new(JwtRegisteredClaimNames.Iss, _jwtSettings.Issuer),
                new(JwtRegisteredClaimNames.Aud, clientId),
                new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(issuedAt).ToUnixTimeSeconds().ToString(),ClaimValueTypes.Integer64),
            };

            if (!string.IsNullOrWhiteSpace(nonce))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, nonce));
            }
            if (scopes.Contains("profile"))
            {
                claims.Add(new Claim("preferred_username", user.UserName));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: clientId,
                claims: claims,
                notBefore: issuedAt,
                expires: issuedAt.AddMinutes(5),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}