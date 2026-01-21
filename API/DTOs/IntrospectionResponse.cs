namespace SSO_IdentityProvider.API.DTOs
{
    public class IntrospectionResponse
    {
        public bool Active { get; set; }

        public string? Sub { get; set; }
        public string? ClientId { get; set; }
        public string? Scope { get; set; }

        public long? Exp { get; set; }
        public long? Iat { get; set; }
        public string? Iss { get; set; }
    }
}
