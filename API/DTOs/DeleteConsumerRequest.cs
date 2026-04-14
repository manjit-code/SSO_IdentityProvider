namespace Esyasoft.Ldap.Gateway.API.DTOs
{
    public class DeleteConsumerRequest
    {
        public string Username { get; set; } = string.Empty;
        public string? DeletedBy { get; set; }
    }
}
