namespace SSO_IdentityProvider.API.DTOs
{
    public class UserSearchResponse
    {
        public string Username { get; set; } = "Unavailable";
        public string FullName { get; set; } = "Unavailable";
        public string Email { get; set; } = "Unavailable";
        public string Department { get; set; } = "Unavailable";
        public string Title { get; set; } = "Unavailable";
        public string PhoneNumber { get; set; } = "Unavailable";
        public string Manager { get; set; } = "Unavailable";
        public string DistinguishedName { get; set; } = "Unavailable";
    }
}
