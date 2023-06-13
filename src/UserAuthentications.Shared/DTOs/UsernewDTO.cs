using UserAuthentications.Infrastructure.Persistence;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Shared.DTOs
{
    //public class UserDTO
    //{
    //    public string Id { get; set; }
    //    public string Email { get; set; }
    //    public string FirstName { get; set; }
    //    public string LastName { get; set; }
    //    public string Email { get; set; }
    //    public string Password { get; set; }
    //    public string Role { get; set; }
    //    public string PhoneNumber { get; set; }
    //    public string Address { get; set; }
    //    public int MobileOTP { get; set; }
    //    public DateTime MobileOTPExpiry { get; set; }
    //    public bool IsEmailVerified { get; set; }
    //    public int EmailOTP { get; set; }
    //    public DateTime EmailOTPExpiry { get; set; }
    //    public bool IsMobileVerified { get; set; }
    //    public DateTime CreatedDate { get; set; }
    //    public DateTime ModifiedDate { get; set; }
    //    // You can add other properties here as needed
    //}


    public class UsernewDTO
    {
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Mobile { get; set; }
        public bool IsEmailVerified { get; set; }
        public bool IsMobileVerified { get; set; }
        public string PasswordHash { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime ModifiedDate { get; set; }
    }

    public class AuthenticationResultDTO
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public bool Success { get; set; }
        public IEnumerable<string> Errors { get; set; }
        public UsernewDTO User { get; set; }
    }

    public class UserRegistrationRequestDTO
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string Mobile { get; set; }
        public string PasswordHash { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime ModifiedDate { get; set; }
    }

    public class SendOtpMobileRequestDTO
    {
        public string Mobile { get; set; }
    }

    public class SendOtpEmailRequestDTO
    {
        public string Email { get; set; }
    }

    public class VerifyOtpMobileRequestDTO
    {
        public string Mobile { get; set; }
        public string Otp { get; set; }
    }

    public class VerifyOtpEmailRequestDTO
    {
        public string Email { get; set; }
        public string Otp { get; set; }
    }

    public class LoginWithPasswordRequestDTO
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class LoginWithOtpRequestDTO
    {
        public string Mobile { get; set; }
        public string Otp { get; set; }
    }

    public class LoginWithGoogleRequestDTO
    {
        public string IdToken { get; set; }
    }

    public class LoginWithFacebookRequestDTO
    {
        public string AccessToken { get; set; }
    }

    public class ChangePasswordRequestDTO
    {
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ForgetPasswordRequestDTO
    {
        public string Email { get; set; }
    }

    public class UpdateProfileRequestDTO
    {
        public string Email { get; set; }
        public string Mobile { get; set; }
    }

}
