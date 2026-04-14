using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Esyasoft.Ldap.Gateway.API.Swagger;
using Esyasoft.Ldap.Gateway.Application.Services;
using Esyasoft.Ldap.Gateway.Domain.Interfaces;
using Esyasoft.Ldap.Gateway.Infrastructure.Configuration;
using Esyasoft.Ldap.Gateway.Infrastructure.Ldap;
using Esyasoft.Ldap.Gateway.Infrastructure.Mapper;
using Esyasoft.Ldap.Gateway.Infrastructure.Security;
using StackExchange.Redis;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Controllers & Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddControllersWithViews();


builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new()
    {
        Title = "SSO Identity Provider",
        Version = "v1"
    });

    options.SchemaFilter<SearchUsersRequestFilter>();
    // Swagger JWT support
    options.AddSecurityDefinition("Bearer", new()
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter JWT as: Bearer {token}"
    });

    options.AddSecurityRequirement(new()
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

});

// Configuration Binding
builder.Services.Configure<LdapSettings>( builder.Configuration.GetSection("LdapSettings"));
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
builder.Services.Configure<LdapInfraSettings>(builder.Configuration.GetSection("LdapInfraSettings"));

// Dependency Injection
builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
builder.Services.AddScoped<ILdapAuthenticator, LdapAuthenticationService>();
builder.Services.AddScoped<IUserRepository, LdapUserRepository>();
builder.Services.AddScoped<ITokenService, JwtTokenService>();
builder.Services.AddScoped<DirectoryService>();
builder.Services.AddScoped<PasswordPolicyValidator>();
builder.Services.AddScoped<IOtpService, OtpService>();

builder.Services.AddScoped<AttributeMapper>();

// JWT Authentication
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var jwtSettings = builder.Configuration
            .GetSection("JwtSettings")
            .Get<JwtSettings>();

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings!.Issuer,

            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,

            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtSettings.Secret)
            ),

            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,

            //  align with token creation
            NameClaimType = ClaimTypes.Name,
            RoleClaimType = ClaimTypes.Role
        };
    });

builder.Services.AddCors(options =>
{
    options.AddPolicy("frontend", policy =>
    {
        policy
            .WithOrigins("http://localhost:5173", "http://localhost:5174")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddHttpClient("OidcServer", (serviceProvider, client) =>
{
    var config = serviceProvider.GetRequiredService<IConfiguration>();
    var baseUrl = config["OidcServer:BaseUrl"]
        ?? throw new InvalidOperationException(
            "'OidcServer:BaseUrl' missing from appsettings.json");
    var internalKey = config["OidcServer:InternalApiKey"]
        ?? throw new InvalidOperationException(
            "'OidcServer:InternalApiKey' missing from appsettings.json");

    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromSeconds(30);

    // Attach the internal API key to every request automatically
    // so the DirectoryController doesn't have to do it manually
    client.DefaultRequestHeaders.Add("X-Internal-Key", internalKey);
})
.ConfigurePrimaryHttpMessageHandler(() =>
    new HttpClientHandler
    {
        // DEV ONLY: Oidc.Server uses a dev HTTPS cert (self-signed)
        // Both services run on Windows localhost — safe to bypass here
        // Remove in production and use a real cert
        ServerCertificateCustomValidationCallback =
            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    });

builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});


// Authorization 
builder.Services.AddAuthorization();


var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseStaticFiles();
app.UseHttpsRedirection();
app.UseCors("frontend");
app.UseAuthentication();
app.UseAuthorization();
app.UseSession();
app.MapControllers();

app.Run();
