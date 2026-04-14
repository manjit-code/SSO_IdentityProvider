using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Esyasoft.Ldap.Gateway.Domain.Entities.Password;
using Esyasoft.Ldap.Gateway.Domain.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Esyasoft.Ldap.Gateway.Infrastructure.Security
{
    public class OtpService : IOtpService
    {
        private readonly IDistributedCache _cache;
        private readonly ILogger<OtpService> _logger;
        private const string OTP_PREFIX = "otp_";
        private const int OTP_EXPIRY_MINUTES = 10;

        public OtpService(IDistributedCache cache, ILogger<OtpService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

        public async Task<string> GenerateAndStoreOtpAsync(string email)
        {
            // TODO: Replace with actual OTP generation when mail system is ready
            // For now, return constant OTP as per requirement
            string otp = "1234";

            var otpData = new OtpData
            {
                Otp = otp,
                Email = email,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(OTP_EXPIRY_MINUTES),
                IsUsed = false,
                Attempts = 0
            };

            var serialized = JsonSerializer.Serialize(otpData);
            var cacheKey = $"{OTP_PREFIX}{email}";

            await _cache.SetStringAsync(cacheKey, serialized, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(OTP_EXPIRY_MINUTES)
            });

            _logger.LogInformation($"OTP generated for {email}: {otp} (DUMMY - Replace with actual email sending)");

            // TODO: Send email with OTP
            // await _emailService.SendOtpEmailAsync(email, otp);

            return otp;
        }

        public async Task<bool> ValidateOtpAsync(string email, string otp)
        {
            var cacheKey = $"{OTP_PREFIX}{email}";
            var serialized = await _cache.GetStringAsync(cacheKey);

            if (string.IsNullOrEmpty(serialized))
            {
                return false;
            }

            var otpData = JsonSerializer.Deserialize<OtpData>(serialized);

            if (otpData == null || otpData.IsUsed || otpData.ExpiresAt < DateTime.UtcNow)
            {
                return false;
            }

            otpData.Attempts++;

            // Allow max 3 attempts
            if (otpData.Attempts > 3)
            {
                await _cache.RemoveAsync(cacheKey);
                return false;
            }

            bool isValid = otpData.Otp == otp;

            if (isValid)
            {
                otpData.IsUsed = true;
                var updatedSerialized = JsonSerializer.Serialize(otpData);
                await _cache.SetStringAsync(cacheKey, updatedSerialized, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(OTP_EXPIRY_MINUTES)
                });
            }
            else
            {
                // Update attempt count
                var updatedSerialized = JsonSerializer.Serialize(otpData);
                await _cache.SetStringAsync(cacheKey, updatedSerialized, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(OTP_EXPIRY_MINUTES)
                });
            }

            return isValid;
        }
    }
}
