using System.DirectoryServices.Protocols;

namespace SSO_IdentityProvider.API.DTOs
{
    public class SearchUsersRequest
    {
        public string? BaseDn { get; set; }

        public Dictionary<string, string>? Filters { get; set; }
        public List<string>? IncludeAttributes { get; set; }

        public string Scope { get; set; } = "Subtree";
        public int MaxResults { get; set; } = 50;
    }
}
