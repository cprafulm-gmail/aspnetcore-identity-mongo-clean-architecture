using UserAuthentications.Infrastructure.Persistence;
using Google.Apis.Auth.OAuth2;
using MongoDB.Bson.Serialization.Attributes;
using System.ComponentModel.DataAnnotations.Schema;

namespace UserAuthentications.Core.Entities
{
    //public class User : IIdentifiable
    //{ 
    //    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    //    public string Id { get; set; }
    //    //public string Email { get; set; }
    //    //public string FirstName { get; set; }
    //    //public string LastName { get; set; }
    //    //public string Email { get; set; }
    //    //public string Password { get; set; }
    //    //public string PhoneNumber { get; set; }
    //    //public string Address { get; set; }
    //    //public int MobileOTP { get; set; }
    //    //public DateTime MobileOTPExpiry { get; set; }
    //    //public bool IsEmailVerified { get; set; }
    //    //public int EmailOTP { get; set; }
    //    //public DateTime EmailOTPExpiry { get; set; }
    //    //public bool IsMobileVerified { get; set; }
    //    public string Email { get; set; }
    //    public string FirstName { get; set; }
    //    public string LastName { get; set; }
    //    public string Email { get; set; }
    //    public string PhoneNumber { get; set; }
    //    public string Password { get; set; }
    //    public string Role { get; set; }
    //    public string Address { get; set; }
    //    public string City { get; set; }
    //    public string State { get; set; }
    //    public string Country { get; set; }
    //    public int ZipCode { get; set; }
    //    public int MobileOTP { get; set; }
    //    public DateTime MobileOTPExpiry { get; set; }
    //    public bool IsEmailVerified { get; set; }
    //    public int EmailOTP { get; set; }
    //    public DateTime EmailOTPExpiry { get; set; }
    //    public bool IsMobileVerified { get; set; }
    //    public DateTime CreatedDate { get; set; }
    //    public DateTime ModifiedDate { get; set; }

    //    //public string Id => base.Id.ToString();
    //}
    public class Usernew : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
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

    public class AuthenticationResult
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public bool Success { get; set; }
        public IEnumerable<string> Errors { get; set; }
        public Usernew User { get; set; }
        public ApplicationUser AppUser { get; set; }
    }
    public class CoTravellerRequest
    {
        public string? Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string Gender { get; set; }
        public DateTime Birthdate { get; set; }

        //public string Mobile { get; set; }
        //public string PasswordHash { get; set; }
        //public string RefreshToken { get; set; }
        //public DateTime RefreshTokenExpiryTime { get; set; }
        //public bool IsActive { get; set; }
        //public DateTime CreatedDate { get; set; }
        //public DateTime ModifiedDate { get; set; }
    }

    public class UserRegistrationRequest
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string PhoneNumber { get; set; }
        public string Gender { get; set; }
        public DateTime Birthdate { get; set; }
        //public string Mobile { get; set; }
        //public string PasswordHash { get; set; }
        //public string RefreshToken { get; set; }
        //public DateTime RefreshTokenExpiryTime { get; set; }
        //public bool IsActive { get; set; }
        //public DateTime CreatedDate { get; set; }
        //public DateTime ModifiedDate { get; set; }
    }

    public class SendOtpMobileRequest
    {
        public string Mobile { get; set; }
    }

    public class SendOtpEmailRequest
    {
        public string Email { get; set; }
    }

    public class VerifyOtpMobileRequest
    {
        public string Mobile { get; set; }
        public string Otp { get; set; }
    }

    public class VerifyOtpEmailRequest
    {
        public string Email { get; set; }
        public string Otp { get; set; }
    }

    public class LoginWithPasswordRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class LoginWithOtpRequest
    {
        public string Mobile { get; set; }
        public string Otp { get; set; }
    }

    public class LoginWithGoogleRequest
    {
        public string IdToken { get; set; }

        // Add Credentials property
        public UserCredential Credentials { get; set; }
    }

    public class LoginWithFacebookRequest
    {
        public string AccessToken { get; set; }
        public string RedirectUri { get; set; }
        public string Code { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

    public class ChangePasswordRequest
    {
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
    }

    public class ForgetPasswordRequest
    {
        public string Email { get; set; }
    }

    public class UpdateProfileRequest
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PhoneNumber { get; set; }
        public DateTime Birthdate { get; set; }
        public string Gender { get; set; }
    }
    public class GoogleAccessTokenDto
    {
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public int expires_in { get; set; }
        public string token_type { get; set; }
        public string id_token { get; set; }
        public object AccessToken { get; set; }
    }
    public class GoogleProfile
    {
        public string Email { get; set; }
        public string GivenName { get; set; }
        public string FamilyName { get; set; }
        public string Code { get; set; }
        public string RedirectUri { get; set; }
    }

}
