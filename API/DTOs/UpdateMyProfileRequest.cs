namespace Esyasoft.Ldap.Gateway.API.DTOs
{
    public class UpdateMyProfileRequest
    {
        public string? DisplayName { get; set; }
        public string? TelephoneNumber { get; set; }
        public string? StreetAddress { get; set; }
        public string? City { get; set; }
        public string? State { get; set; }
        public string? PostalCode { get; set; }
        public string? Country { get; set; }
        public string? NewPassword { get; set; }
    }
}
