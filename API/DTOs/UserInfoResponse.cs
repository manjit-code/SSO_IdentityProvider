namespace SSO_IdentityProvider.API.DTOs
{
    public class UserInfoResponse
    {
        public string Sub { get; set; } = string.Empty;
        public string PreferredUsername { get; set; } = string.Empty;

        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? PhoneNumber { get; set; }

        public string? Department { get; set; }
        public string? Title { get; set; }

        public IReadOnlyCollection<string> Groups { get; set; } = Array.Empty<string>();
    }
}
