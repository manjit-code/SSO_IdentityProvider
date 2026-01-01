namespace SSO_IdentityProvider.API.DTOs
{
    public class MyProfileResponse
    {
        public string Username { get; set; } = string.Empty;
        public string DistinguishedName { get; set; } = string.Empty;
        public string? DisplayName { get; set; }
        public string? Email { get; set; }
        public string? Phone { get; set; }
        public string? Department { get; set; }
        public string? Title { get; set; }
        public List<string> Groups { get; set; } = new();
    }
}
