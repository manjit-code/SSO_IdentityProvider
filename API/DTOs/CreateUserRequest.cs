namespace SSO_IdentityProvider.API.DTOs
{
    public class CreateUserRequest
    {
        public string FullName { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string TelephoneNumber { get; set; } = string.Empty;
        public LocationDto? Location { get; set; }
    }

    public class LocationDto
    {
        public string? City { get; set; } 
        public string? State { get; set; }
        public string? PostalCode { get;set; }
    }
}
