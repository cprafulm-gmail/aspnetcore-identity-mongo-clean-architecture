using UserAuthentications.Core.Entities;
using UserAuthentications.Shared.DTOs;
using MimeKit.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Operation.Abstractions
{
    public interface IUsernewService
    {
        Task<AuthenticationResult> RegisterAsync(UserRegistrationRequest request);
        Task SendOtpToMobileAsync(SendOtpMobileRequest request);
        Task SendOtpToEmailAsync(SendOtpEmailRequest request);
        Task<AuthenticationResult> VerifyOtpOnMobileAsync(VerifyOtpMobileRequest request);
        Task<AuthenticationResult> VerifyOtpOnEmailAsync(VerifyOtpEmailRequest request);
        Task<AuthenticationResult> LoginWithPasswordAsync(LoginWithPasswordRequest request);
        Task<AuthenticationResult> LoginWithOtpAsync(LoginWithOtpRequest request);
        Task<AuthenticationResult> LoginWithGoogleAsync(LoginWithGoogleRequest request);
       // Task<AuthenticationResult> LoginWithFacebookAsync(LoginWithFacebookRequest request);
        Task<AuthenticationResult> ChangePasswordAsync(string email, ChangePasswordRequest request);
        Task ForgetPasswordAsync(ForgetPasswordRequest request);
        //Task<AuthenticationResult> UpdateProfileAsync(string email, UpdateProfileRequest request);

    }
}
