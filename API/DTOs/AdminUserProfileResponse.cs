namespace SSO_IdentityProvider.API.DTOs
{
    public class AdminUserProfileResponse
    {
        public string Username { get; set; } = "Unavailable";
        public string DistinguishedName { get; set; } = "Unavailable";

        public string DisplayName { get; set; } = "Unavailable";
        public string Email { get; set; } = "Unavailable";
        public string Phone { get; set; } = "Unavailable";
        public string Department { get; set; } = "Unavailable";
        public string Title { get; set; } = "Unavailable";
        public string Manager { get; set; } = "Unavailable";

        public bool AccountEnabled { get; set; }

        public List<string> Groups { get; set; } = new();

        public DateTime? WhenCreated { get; set; }
        public DateTime? WhenChanged { get; set; }
    }
}
