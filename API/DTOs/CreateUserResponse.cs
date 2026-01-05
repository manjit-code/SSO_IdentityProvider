namespace SSO_IdentityProvider.API.DTOs
{
    public class CreateUserResponse
    {
        public string Username { get; set; } = string.Empty;
        public string InitialPassword { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
    }
}