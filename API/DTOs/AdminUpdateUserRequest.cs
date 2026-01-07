namespace SSO_IdentityProvider.API.DTOs
{
    public class AdminUpdateUserRequest
    {
        public string Email { get; set; } = string.Empty;
        public string? Department { get; set; }   // OU move
        public string? ManagerEmail { get; set; } // manager DN resolved internally
        public string? Title { get; set; }
    }
}
