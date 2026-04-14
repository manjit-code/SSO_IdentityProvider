using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Esyasoft.Ldap.Gateway.API.DTOs;
using Esyasoft.Ldap.Gateway.Domain.Entities;
using Esyasoft.Ldap.Gateway.Domain.Entities.Password;
using Esyasoft.Ldap.Gateway.Domain.Interfaces;
using Esyasoft.Ldap.Gateway.Infrastructure.Configuration;
using Esyasoft.Ldap.Gateway.Infrastructure.Security;
using System.DirectoryServices.Protocols;
using System.Net;

namespace Esyasoft.Ldap.Gateway.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IAuthenticationService _authenticationService;
        private readonly LdapSettings _ldapSettings;
        private readonly IUserRepository _userRepository;
        private readonly ILdapAuthenticator _ldapAuthenticator;
        private readonly IOtpService _otpService;
        private readonly PasswordPolicyValidator _passwordPolicyValidator;
        private readonly ILogger<AuthController> _logger;
        public AuthController(IAuthenticationService authenticationService,IOptions<LdapSettings> options, IUserRepository userRepository,ILdapAuthenticator ldapAuthenticator,IOtpService otpService,PasswordPolicyValidator passwordPolicyValidator,ILogger<AuthController> logger)
        {
            _authenticationService = authenticationService;
            _ldapSettings = options.Value;
            _userRepository = userRepository;
            _ldapAuthenticator = ldapAuthenticator;
            _otpService = otpService;
            _passwordPolicyValidator = passwordPolicyValidator;
            _logger = logger;
        }


        [HttpGet("ldap-health")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public IActionResult LdapHealth()
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(
                    _ldapSettings.Host,
                    _ldapSettings.Port,
                    _ldapSettings.UseSsl,
                    false
                );

                var credential = new NetworkCredential(_ldapSettings.username, _ldapSettings.password);
                using var connection = new LdapConnection(identifier)
                {
                    AuthType = AuthType.Basic,
                    Credential = credential
                };

                connection.SessionOptions.ProtocolVersion = 3;
                if (_ldapSettings.UseSsl)
                {
                    connection.SessionOptions.SecureSocketLayer = true;
                    connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;
                }
                connection.Bind();

                return Ok(new
                {
                    Status = "LDAP reachable and configured credentials are valid",
                    Host = _ldapSettings.Host,
                    Port = _ldapSettings.Port,
                    UseSsl = _ldapSettings.UseSsl
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }



        [HttpPost("login")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (request == null || string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Username and password must be provided.");
            }

            try
            {
                var token = await _authenticationService.AuthenticateAsync(request.Username, request.Password);
                if (token == null) {
                    return Unauthorized("Invalid username or password.");
                }
                return Ok(new TokenResponse { AccessToken = token });
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized("Invalid username or password.");
            }
            catch (Exception ex)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, $"An error occurred: {ex.Message}");
            }
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(OtpResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            if (request == null || string.IsNullOrEmpty(request.Email))
            {
                return BadRequest("Email address is required.");
            }

            _logger.LogInformation("Password reset requested for email: {Email}", request.Email);

            try
            {
                // Check if user exists
                using var connection = _ldapAuthenticator.BindAsServiceAccount();
                var user = await _userRepository.GetByUsernameAsync(connection, request.Email);

                if (user == null)
                {
                    _logger.LogWarning("Password reset attempted for non-existent email: {Email}", request.Email);
                    return Ok(new OtpResponse
                    {
                        Message = "An OTP has been sent to your mail."
                    });
                }

                // Generate and store OTP
                var otp = await _otpService.GenerateAndStoreOtpAsync(request.Email);

                var response = new OtpResponse
                {
                    Message = "OTP has been sent to your email address."
                };

                // Include OTP in response only in development for testing
                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                {
                    response.Otp = otp;
                    _logger.LogInformation("Development mode: OTP for {Email} is {Otp}", request.Email, otp);
                }

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing forgot password request for {Email}", request.Email);
                return StatusCode(500, "An error occurred processing your request.");
            }
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            // Validate request
            if (request == null || string.IsNullOrEmpty(request.Email) ||
                string.IsNullOrEmpty(request.Otp) || string.IsNullOrEmpty(request.NewPassword))
            {
                return BadRequest("Email, OTP, and new password are required.");
            }

            if (request.NewPassword != request.ConfirmPassword)
            {
                return BadRequest("Password and confirmation do not match.");
            }

            _logger.LogInformation("Password reset attempt for email: {Email}", request.Email);

            try
            {
                // Verify OTP
                var isValidOtp = await _otpService.ValidateOtpAsync(request.Email, request.Otp);
                if (!isValidOtp)
                {
                    _logger.LogWarning("Invalid or expired OTP for email: {Email}", request.Email);
                    return Unauthorized("Invalid or expired OTP.");
                }

                // Get user from LDAP
                using var connection = _ldapAuthenticator.BindAsServiceAccount();
                var user = await _userRepository.GetByUsernameAsync(connection, request.Email);

                if (user == null)
                {
                    _logger.LogWarning("Password reset attempted for non-existent user: {Email}", request.Email);
                    return NotFound("User not found.");
                }

                // Extract username using AttributeMapper
                string? username = null;
                try
                {
                    // Get user profile to extract username consistently
                    var userProfile = await _userRepository.GetMyProfileAsync(connection, request.Email);
                    username = userProfile?.Username ?? user.UserName;
                }
                catch
                {
                    // Fallback to username from user object
                    username = user.UserName;
                }

                // Validate password against policy
                var validationResult = _passwordPolicyValidator.ValidatePassword(request.NewPassword, username);

                if (!validationResult.IsValid)
                {
                    return BadRequest(new PasswordValidationResponse
                    {
                        IsValid = false,
                        Errors = validationResult.Errors
                    });
                }

                // Update password using repository
                var updateProfile = new UpdateMyProfile
                {
                    NewPassword = request.NewPassword
                };

                await _userRepository.UpdateUserProfileAsync(user.DistinguishedName, updateProfile);

                _logger.LogInformation("Password successfully reset for user: {Username}", user.UserName);

                return Ok(new
                {
                    Message = "Password has been successfully reset. You can now login with your new password."
                });
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("Password validation failed"))
            {
                return BadRequest(new PasswordValidationResponse
                {
                    IsValid = false,
                    Errors = new List<string> { ex.Message.Replace("Password validation failed: ", "") }
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password for {Email}", request.Email);
                return StatusCode(500, "An error occurred while resetting your password.");
            }
        }

        // This endpoint is for internal use by the frontend to validate password strength before submission.
        [HttpPost("validate-password")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(PasswordValidationResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public IActionResult ValidatePassword([FromBody] ValidatePasswordRequest request)
        {
            if (request == null || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest("Password is required.");
            }

            try
            {
                var validationResult = _passwordPolicyValidator.ValidatePassword(
                    request.Password
                );

                return Ok(new PasswordValidationResponse
                {
                    IsValid = validationResult.IsValid,
                    Errors = validationResult.Errors
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating password");
                return StatusCode(500, "An error occurred while validating password.");
            }
        }

        [HttpGet("user-exists/{username}")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> UserExists(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return BadRequest("Username is required.");

            try
            {
                // Use service account connection (read-only search, not a BIND as the user)
                using var connection = _ldapAuthenticator.BindAsServiceAccount();

                // Search for the user by uid in OpenLDAP
                var user = await _userRepository.GetByUsernameAsync(connection, username);

                return Ok(new { exists = user != null });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UserExists] Failed to check username {Username}", username);
                return StatusCode(500, "Unable to reach the directory service.");
            }
        }

        /// <summary>
        /// Called by Oidc.Server → Ldap.Service → LdapService.AuthenticateAsync().
        /// Returns a structured result so Oidc.Server can distinguish wrong
        /// password, account locked, user not found, and service errors.
        ///
        /// All logic lives in IAuthenticationService.LoginDetailedAsync().
        /// This controller method is a thin pass-through only.
        /// </summary>
        [HttpPost("login-detailed")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> LoginDetailed([FromBody] LoginRequest request)
        {
            if (request == null ||
                string.IsNullOrWhiteSpace(request.Username) ||
                string.IsNullOrWhiteSpace(request.Password))
                return BadRequest("Username and password are required.");

            _logger.LogInformation("[LoginDetailed] Auth request for {Username}", request.Username);

            var result = await _authenticationService.LoginDetailedAsync(request.Username, request.Password);

            _logger.LogInformation(
                "[LoginDetailed] Result for {Username}: {Result}",
                request.Username, result.Result);

            return Ok(result);
        }

        /// <summary>
        /// Called by Oidc.Server → Ldap.Service → LdapService.AccountLockoutAsync().
        /// Returns lockout status without verifying the password.
        ///
        /// All logic lives in IAuthenticationService.GetLockoutStatusAsync().
        /// This controller method is a thin pass-through only.
        /// </summary>
        [HttpGet("lockout-status/{username}")]
        [AllowAnonymous]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> GetLockoutStatus(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return BadRequest("Username is required.");

            _logger.LogInformation(
                "[LockoutStatus] Check for {Username}", username);

            var result = await _authenticationService
                .GetLockoutStatusAsync(username);

            return Ok(result);
        }
    }

}
