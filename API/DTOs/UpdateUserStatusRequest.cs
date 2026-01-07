namespace SSO_IdentityProvider.API.DTOs
{
    public class UpdateUserStatusRequest
    {
        public string Email { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
    }
}
