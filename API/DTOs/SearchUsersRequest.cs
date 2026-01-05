using System.DirectoryServices.Protocols;

namespace SSO_IdentityProvider.API.DTOs
{
    public class SearchUsersRequest
    {
        public Dictionary<string, string>? Filters { get; set; }
        public List<string>? IncludeAttributes { get; set; }
        public int MaxResults { get; set; } = 50;
    }
}
