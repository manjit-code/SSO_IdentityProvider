using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Infrastructure.Configuration
{
    public class PasswordPolicySettings
    {
        // Minimum length requirements
        public int MinimumLength { get; set; } = 8;
        public int MaximumLength { get; set; } = 128;

        // Character class requirements
        public bool RequireUppercase { get; set; } = true;
        public bool RequireLowercase { get; set; } = true;
        public bool RequireDigit { get; set; } = true;
        public bool RequireSpecialCharacter { get; set; } = true;
        public string AllowedSpecialCharacters { get; set; } = "!@#$%^&*()_-+={}[]|\\:;\"'<>,.?/~`";

        // Password history (prevent reuse)
        public int PasswordHistoryCount { get; set; } = 5;

        // Password expiration (in days)
        public int PasswordExpiryDays { get; set; } = 90;

        // Account lockout settings
        public int MaxFailedAttempts { get; set; } = 5;
        public int LockoutDurationMinutes { get; set; } = 15;

        // Common password blacklist
        public string[] CommonPasswordBlacklist { get; set; } = new[]
        {
            "password", "123456", "qwerty", "admin", "welcome",
            "password123", "admin123", "letmein", "monkey", "dragon"
        };

        // Prevent sequential characters ("abc", "123")
        public bool PreventSequentialCharacters { get; set; } = true;
        public int SequentialCharacterLength { get; set; } = 3;

        // Prevent repeated characters ("aaa", "111")
        public bool PreventRepeatedCharacters { get; set; } = true;
        public int RepeatedCharacterLength { get; set; } = 3;

        // Prevent username in password
        public bool PreventUsernameInPassword { get; set; } = true;
    }
}
