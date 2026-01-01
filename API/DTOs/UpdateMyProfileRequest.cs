namespace SSO_IdentityProvider.API.DTOs
{
    public class UpdateMyProfileRequest
    {
        public string? DisplayName { get; set; }
        public string? TelephoneNumber { get; set; }
        public string? Mobile { get; set; }
        public string? StreetAddress { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? PostalCode { get; set; }
        public string? NewPassword { get; set; }
    }
}
