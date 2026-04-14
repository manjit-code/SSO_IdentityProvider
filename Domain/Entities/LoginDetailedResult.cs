namespace Esyasoft.Ldap.Gateway.Domain.Entities
{
    public class LoginDetailedResult
    {
        /// <summary>
        /// One of: "success", "wrong_password", "account_locked",
        ///         "user_not_found", "provider_error", "not_locked"
        /// These exact strings are expected by LdapService.LoginDetailedDto
        /// in Esyasoft.Identity.Ldap.Service.
        /// </summary>
        public string Result { get; set; } = string.Empty;

        /// <summary>
        /// Seconds until the account unlocks.
        /// Null when not locked.
        /// -1 means permanently locked — admin must unlock manually.
        /// Only set when Result = "account_locked".
        /// </summary>
        public int? LockoutRemainingSeconds { get; set; }

        /// <summary>
        /// Human-readable message. Null on success.
        /// Never expose internal LDAP error details here.
        /// </summary>
        public string? Message { get; set; }

        // ── Static factory methods ────────────────────────────────

        public static LoginDetailedResult Success()
            => new() { Result = "success" };

        public static LoginDetailedResult WrongPassword()
            => new()
            {
                Result = "wrong_password",
                Message = "Invalid username or password."
            };

        public static LoginDetailedResult UserNotFound()
            => new()
            {
                // Same message as WrongPassword — prevents username enumeration.
                Result = "user_not_found",
                Message = "Invalid username or password."
            };

        public static LoginDetailedResult AccountLocked(int? remainingSeconds)
            => new()
            {
                Result = "account_locked",
                LockoutRemainingSeconds = remainingSeconds,
                Message = remainingSeconds == -1
                    ? "Account is permanently locked. Contact your administrator."
                    : $"Account locked. Try again in {remainingSeconds} seconds."
            };

        public static LoginDetailedResult NotLocked()
            => new()
            {
                Result = "not_locked",
                Message = "Account is not locked."
            };

        public static LoginDetailedResult ProviderError(string? detail = null)
            => new()
            {
                Result = "provider_error",
                Message = detail ?? "Authentication service encountered an error."
            };
    }
}