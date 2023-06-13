using UserAuthentications.Core.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Operation.Abstractions
{
    public interface IAuthService
    {
        Task<AuthenticationResult> RegisterAsync(UserRegistrationRequest request);
        Task<AuthenticationResult> AuthenticateAsync(string email, string password);
        Task<AuthenticationResult> UpdateProfileAsync(string email, UpdateProfileRequest request);
        Task<AuthenticationResult> GetUserByEmailAsync(string userId);
        Task<AuthenticationResult> AddCoTravelerAsync(string userId, CoTravellerRequest request);
        Task<AuthenticationResult> UpdateCoTravellerAsync(string userId, CoTravellerRequest request);
        Task<List<CoTraveller>> GetCoTravelersAsync(string userId);
        Task<AuthenticationResult> RemoveCoTravelerAsync(string userId, string coTravellerId);

        //Task SendOtpToMobileAsync(SendOtpMobileRequest request);
        //Task SendOtpToEmailAsync(SendOtpEmailRequest request);
        //Task<AuthenticationResult> VerifyOtpOnMobileAsync(VerifyOtpMobileRequest request);
        //Task<AuthenticationResult> VerifyOtpOnEmailAsync(VerifyOtpEmailRequest request);
        //Task<AuthenticationResult> LoginWithPasswordAsync(LoginWithPasswordRequest request);
        //Task<AuthenticationResult> LoginWithOtpAsync(LoginWithOtpRequest request);
        //Task<AuthenticationResult> LoginWithGoogleAsync(LoginWithGoogleRequest request);
        ////Task<AuthenticationResult> LoginWithFacebookAsync(LoginWithFacebookRequest request);
        //Task<AuthenticationResult> ChangePasswordAsync(string email, ChangePasswordRequest request);
        //Task ForgetPasswordAsync(ForgetPasswordRequest request);
        //Task<AuthenticationResult> UpdateProfileAsync(string email, UpdateProfileRequest request);
    }
}
