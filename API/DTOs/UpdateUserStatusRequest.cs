namespace Esyasoft.Ldap.Gateway.API.DTOs
{
    public class UpdateUserStatusRequest
    {
        public string Email { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
    }
}
