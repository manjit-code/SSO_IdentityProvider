using Microsoft.OpenApi.Models;
using SSO_IdentityProvider.API.DTOs;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace SSO_IdentityProvider.API.Swagger
{
    public class SearchUsersRequestFilter : ISchemaFilter
    {
        public void Apply(OpenApiSchema schema, SchemaFilterContext context)
        {
            if (context.Type == typeof(SearchUsersRequest))
            {
                // Remove legacy properties from Swagger documentation
                if (schema.Properties.ContainsKey("filters"))
                    schema.Properties.Remove("filters");

                if (schema.Properties.ContainsKey("includeAttributes"))
                    schema.Properties.Remove("includeAttributes");
            }
        }
    }
}
