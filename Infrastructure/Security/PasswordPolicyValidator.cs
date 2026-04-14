using Microsoft.Extensions.Options;
using Esyasoft.Ldap.Gateway.Domain.Entities.Password;
using Esyasoft.Ldap.Gateway.Infrastructure.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Infrastructure.Security
{
    public class PasswordPolicyValidator
    {
        private readonly PasswordPolicySettings _settings;

        public PasswordPolicyValidator(IOptions<PasswordPolicySettings> settings)
        {
            _settings = settings.Value;
        }

        public ValidationResult ValidatePassword(string password, string? username = null)
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(password))
            {
                errors.Add("Password cannot be empty");
                return new ValidationResult(false, errors);
            }

            if (password.Length < _settings.MinimumLength)
            {
                errors.Add($"Password must be at least {_settings.MinimumLength} characters long");
            }

            if (password.Length > _settings.MaximumLength)
            {
                errors.Add($"Password cannot exceed {_settings.MaximumLength} characters");
            }

            if (_settings.RequireUppercase && !password.Any(char.IsUpper))
            {
                errors.Add("Password must contain at least one uppercase letter");
            }

            if (_settings.RequireLowercase && !password.Any(char.IsLower))
            {
                errors.Add("Password must contain at least one lowercase letter");
            }

            if (_settings.RequireDigit && !password.Any(char.IsDigit))
            {
                errors.Add("Password must contain at least one digit");
            }

            if (_settings.RequireSpecialCharacter)
            {
                var specialChars = _settings.AllowedSpecialCharacters.ToCharArray();
                if (!password.Any(c => specialChars.Contains(c)))
                {
                    var specialCharsDisplay = _settings.AllowedSpecialCharacters
                        .Replace("\\", "\\\\")
                        .Replace("\"", "\\\"");
                    errors.Add($"Password must contain at least one special character: {specialCharsDisplay}");
                }
            }

            // Check against common password blacklist
            if (_settings.CommonPasswordBlacklist != null)
            {
                foreach (var commonPassword in _settings.CommonPasswordBlacklist)
                {
                    if (password.Contains(commonPassword, StringComparison.OrdinalIgnoreCase))
                    {
                        errors.Add("Password contains a common word that is too easy to guess");
                        break;
                    }
                }
            }

            if (_settings.PreventSequentialCharacters)
            {
                if (HasSequentialCharacters(password, _settings.SequentialCharacterLength))
                {
                    errors.Add($"Password contains {_settings.SequentialCharacterLength} or more sequential characters");
                }
            }

            if (_settings.PreventRepeatedCharacters)
            {
                if (HasRepeatedCharacters(password, _settings.RepeatedCharacterLength))
                {
                    errors.Add($"Password contains {_settings.RepeatedCharacterLength} or more repeated characters");
                }
            }
            if (_settings.PreventUsernameInPassword && !string.IsNullOrWhiteSpace(username))
            {
                var usernameParts = username.Split(new[] { '@', '.', '_', '-', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var part in usernameParts)
                {
                    if (part.Length >= 3 && password.Contains(part, StringComparison.OrdinalIgnoreCase))
                    {
                        errors.Add("Password contains part of the username");
                        break;
                    }
                }
            }

            return new ValidationResult(errors.Count == 0, errors);
        }

        private bool HasSequentialCharacters(string password, int minLength)
        {
            string sequences = "abcdefghijklmnopqrstuvwxyz0123456789";

            for (int i = 0; i <= password.Length - minLength; i++)
            {
                string substring = password.Substring(i, minLength).ToLower();

                // Check forward sequence (abc)
                if (sequences.Contains(substring))
                    return true;

                // Check reverse sequence (cba)
                char[] charArray = substring.ToCharArray();
                Array.Reverse(charArray);
                string reversed = new string(charArray);
                if (sequences.Contains(reversed))
                    return true;

                // Check keyboard rows (qwerty, asdfgh, zxcvbn)
                string[] keyboardRows = { "qwertyuiop", "asdfghjkl", "zxcvbnm" };
                foreach (var row in keyboardRows)
                {
                    if (row.Contains(substring))
                        return true;
                }
            }

            return false;
        }

        private bool HasRepeatedCharacters(string password, int minLength)
        {
            for (int i = 0; i <= password.Length - minLength; i++)
            {
                char currentChar = password[i];
                bool allSame = true;

                for (int j = 1; j < minLength; j++)
                {
                    if (password[i + j] != currentChar)
                    {
                        allSame = false;
                        break;
                    }
                }

                if (allSame)
                    return true;
            }

            return false;
        }
    }

}
