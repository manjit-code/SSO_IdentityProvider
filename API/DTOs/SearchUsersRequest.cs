using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.DirectoryServices.Protocols;
using System.Text.Json.Serialization;

namespace Esyasoft.Ldap.Gateway.API.DTOs
{
    public class SearchUsersRequest
    {
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Dictionary<string, string>? Filters { get; set; }
        public UserSearchFilters? SearchFilters { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<string>? IncludeAttributes { get; set; }
        public UserAttributesRequest? Attributes { get; set; }

        [DefaultValue(10)]
        [Range(1,1000)]
        public int MaxResults { get; set; } = 10;
    }
}
