using AutoMapper;
using UserAuthentications.Core.Entities;
using UserAuthentications.Infrastructure.Persistence;
using UserAuthentications.Operation.Abstractions;
using UserAuthentications.Shared.DTOs;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using MimeKit.Cryptography;
using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AspNetCore.Identity.MongoDbCore.Models;
using UserAuthentications.Core.Entities.Identity;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Plus.v1;

using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Services;
using Newtonsoft.Json;

namespace UserAuthentications.Operation.Implementation
{
    public static class GoogleAuthConsts
    {
        public const string PlusLoginScope = "https://www.googleapis.com/auth/plus.login";
    }
    public class UsernewService : IUsernewService
    {
        private readonly IMapper _mapper;
        private readonly IMongoRepository<Usernew> _userRepository;
        //private readonly IEmailService _emailService;
        private readonly ICacheService _cacheService;
        private readonly Random _random = new Random();
        //private readonly IUserRepository _userRepository;
        //private readonly ISmsService _smsService;
        //private readonly IJwtService _jwtService;

        public UsernewService(IMapper mapper, IMongoRepository<Usernew> userRepository,  ICacheService cacheService)
        {
            _mapper = mapper;
            _userRepository = userRepository;
            //_emailService = emailService;
            _cacheService = cacheService;
            //_smsService = smsService;
            //_jwtService = jwtService;
        }

        public async Task<AuthenticationResult> RegisterAsync(UserRegistrationRequest request)
        {
            var existingUser = await _userRepository.GetAsync(u => u.Email == request.Email);

            if (existingUser != null)
            {
                return new AuthenticationResult
                {
                    Errors = new[] { "User with this email already exists" }
                };
            }

            var user = new Usernew
            {
                Id = ObjectId.GenerateNewId().ToString(),
                FirstName = request.FirstName,
                LastName = request.LastName,
                Email = request.Email,
                PasswordHash = HashPassword(request.PasswordHash),
                IsActive = true,
                CreatedDate = DateTime.UtcNow
            };

            await _userRepository.AddAsync(user);

            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateToken(user),
                User = user
            };
        }


        private string HashPassword(string password)
        {
            using (var hmac = new HMACSHA512())
            {
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                var hash = hmac.ComputeHash(passwordBytes);
                return Convert.ToBase64String(hash);
            }
        }

        private string GenerateToken(Usernew user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("PRAFULCHAUHAN123");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
            new Claim(ClaimTypes.Name, user.Id),
            new Claim(ClaimTypes.Email, user.Email)
        }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public async Task SendOtpToMobileAsync(SendOtpMobileRequest request)
        {

            var user = await _userRepository.GetAsync(u => u.Mobile == request.Mobile);
            if (user != null)
            {
                // Generate a random 6-digit OTP
                var otp = _random.Next(100000, 999999).ToString();

                // Save the OTP in the cache with a 30-minute expiry time
                await _cacheService.SetAsync($"MobileOtp:{request.Mobile}", otp, TimeSpan.FromMinutes(30));
            }

            // Send the OTP via email
            //await _emailService.SendOtpEmailAsync(request.Mobile, otp);
            //var accountSid = "your_account_sid";
            //var authToken = "your_auth_token";
            //TwilioClient.Init(accountSid, authToken);

            //var message = await MessageResource.CreateAsync(
            //    body: $"Your OTP is: {request.Otp}",
            //    from: new Twilio.Types.PhoneNumber("your_twilio_phone_number"),
            //    to: new Twilio.Types.PhoneNumber(request.MobileNumber)
            //);
            // TODO: Implement sending OTP to mobile logic
        }

        public async Task SendOtpToEmailAsync(SendOtpEmailRequest request)
        {
            // TODO: Implement sending OTP to email logic


            var user = await _userRepository.GetAsync(u => u.Email == request.Email);
            if (user != null)
            {
                // Generate a random 6-digit OTP
                var otp = _random.Next(100000, 999999).ToString();

                // Save the OTP in the cache with a 30-minute expiry time
                await _cacheService.SetAsync($"EmailOtp:{request.Email}", otp, TimeSpan.FromMinutes(30));
            }
        }

        public async Task<AuthenticationResult> VerifyOtpOnMobileAsync(VerifyOtpMobileRequest request)
        {
            // TODO: Implement verifying OTP on mobile logic
            try
            {

                var user = await _userRepository.GetAsync(u => u.Mobile == request.Mobile);
                if (user == null)
                {
                    return new AuthenticationResult
                    {
                        Errors = new[] { "User not found" }
                    };
                }
                else
                {
                    var hasValue = await _cacheService.GetAsync($"MobileOtp:{request.Mobile}");
                    if (hasValue != null && hasValue == request.Otp)//verificationCheck.Status == "approved")
                    {
                        user.IsMobileVerified = true;
                        await _userRepository.UpdateAsync(user);
                        await _cacheService.RemoveAsync($"MobileOtp:{request.Mobile}");

                        return new AuthenticationResult { Success = true };
                    }
                    else
                    {
                        return new AuthenticationResult { Errors = new[] { "Invalid OTP code" } };
                    }
                }
            }
            catch (Exception ex)
            {
                // Log exception
                return new AuthenticationResult { Errors = new[] { "An error occurred while verifying OTP code" } };
            }
        }


        public async Task<AuthenticationResult> VerifyOtpOnEmailAsync(VerifyOtpEmailRequest request)
        {
            // TODO: Implement verifying OTP on mobile logic
            try
            {

                var user = await _userRepository.GetAsync(u => u.Email == request.Email);
                if (user == null)
                {
                    return new AuthenticationResult
                    {
                        Errors = new[] { "User not found" }
                    };
                }
                else
                {
                    var sfsd = await _cacheService.GetAsync($"EmailOtp:{request.Email}");
                    if (true)//verificationCheck.Status == "approved")
                    {
                        user.IsMobileVerified = true;
                        await _userRepository.UpdateAsync(user);

                        await _cacheService.RemoveAsync($"EmailOtp:{request.Email}");
                        return new AuthenticationResult { Success = true };
                    }
                    else
                    {
                        return new AuthenticationResult { Errors = new[] { "Invalid OTP code" } };
                    }
                }
            }
            catch (Exception ex)
            {
                // Log exception
                return new AuthenticationResult { Errors = new[] { "An error occurred while verifying OTP code" } };
            }
        }


        public async Task<AuthenticationResult> LoginWithPasswordAsync(LoginWithPasswordRequest request)
        {
            // TODO: Implement login with password logic
            var user = await _userRepository.GetAsync(u => u.Email == request.Email);

            if (user == null)
            {
                return new AuthenticationResult
                {
                    Errors = new[] { "Invalid email or password" }
                };
            }

            //if (!VerifyPassword(request.Password, user.Password))
            //{
            //    return new AuthenticationResult
            //    {
            //        Errors = new[] { "Invalid email or password" }
            //    };
            //}


            // Check if the user exists and if the password matches
            if (user == null || !user.PasswordHash.Equals(HashPassword(request.Password)))
            {
                throw new Exception("Invalid email or password");
            }

    //        var claims = new List<Claim>
    //{
    //    new Claim(ClaimTypes.NameIdentifier, user.Id),
    //    new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"),
    //    new Claim(ClaimTypes.Email, user.Email)
    //};

    //        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
    //        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    //        var tokenDescriptor = new SecurityTokenDescriptor
    //        {
    //            Subject = new ClaimsIdentity(claims),
    //            Expires = DateTime.UtcNow.AddMinutes(30),
    //            SigningCredentials = credentials
    //        };

    //        var tokenHandler = new JwtSecurityTokenHandler();
    //        var token = tokenHandler.CreateToken(tokenDescriptor);

            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateToken(user),
                User = user
            };
        }

        public async Task<AuthenticationResult> LoginWithOtpAsync(LoginWithOtpRequest request)
        {
            // TODO: Implement login with OTP logic
            var cacheKey = $"MobileOtp:{request.Mobile}";

            var cachedOtp = await _cacheService.GetAsync(cacheKey);
            if (cachedOtp != request.Otp)
            {
                return new AuthenticationResult
                {
                    Errors = new[] { "Invalid OTP" }
                };
            }

            var user = await _userRepository.GetAsync(u => u.Email == request.Mobile);

            if (user == null)
            {
                return new AuthenticationResult
                {
                    Errors = new[] { "User does not exist" }
                };
            }

            await _cacheService.RemoveAsync(cacheKey);

            var token = GenerateToken(user);

            return new AuthenticationResult
            {
                Success = true,
                Token = token,
                User = user
            };
        }

        public async Task<AuthenticationResult> LoginWithGoogleAsync(LoginWithGoogleRequest request)
        {
            try
            {

                string json = "{\"web\":{\"client_id\":\"977119073212-86broul2astpqvc50qsrvjkgurslmaio.apps.googleusercontent.com\",\"project_id\":\"friendly-magpie-382213\",\"auth_uri\":\"https://accounts.google.com/o/oauth2/auth\",\"token_uri\":\"https://oauth2.googleapis.com/token\",\"auth_provider_x509_cert_url\":\"https://www.googleapis.com/oauth2/v1/certs\",\"client_secret\":\"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\",\"redirect_uris\":[\"https://localhost:7006/api/UserAuthentication/login/google/signin-google\"],\"javascript_origins\":[\"https://localhost:7006\"]}}";
                UserCredential credential = JsonConvert.DeserializeObject<UserCredential>(json);
                //UserCredential credential;
                using (var stream = new MemoryStream(Encoding.UTF8.GetBytes("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")))
                {
                    credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
                        GoogleClientSecrets.Load(stream).Secrets,
                        new[] { GoogleAuthConsts.PlusLoginScope },
                        "user",
                        CancellationToken.None
                    );
                }

                var service = new PlusService(new BaseClientService.Initializer()
                {
                    HttpClientInitializer = credential,
                    ApplicationName = "_appSettings.GoogleAppName"
                });

                var profile = await service.People.Get("me").ExecuteAsync();
                var user = new Usernew
                {
                    Email = profile.Emails?.FirstOrDefault()?.Value,
                    FirstName = profile.Name?.GivenName,
                    LastName = profile.Name?.FamilyName,
                    //ProfileImageUrl = profile.Image?.Url
                };

                // TODO: Check if user exists in your database and perform any necessary actions

                var jwtToken = GenerateToken(user);
                return new AuthenticationResult
                {
                    Success = true,
                    Token = jwtToken
                };
            }
            catch (Exception ex)
            {
                return new AuthenticationResult
                {
                    Success = false,
                    //ErrorMessage = new List<string> { ex.Message }
                };
            }
        }
        //public async Task<AuthenticationResult> LoginWithGoogleAsync(LoginWithGoogleRequest request)
        //{
        //    try
        //    {
        //        //UserCredential credential;
        //        //using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(request.Credentials)))
        //        //{
        //        //    credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
        //        //        GoogleClientSecrets.Load(stream).Secrets,
        //        //        new[] { Google.Apis.Auth.OAuth2.GoogleAuthConsts.PlusLoginScope },
        //        //        "user",
        //        //        CancellationToken.None
        //        //    );
        //        //}
        //        var credential = new UserCredential(new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer
        //        {
        //            ClientSecrets = GoogleClientSecrets.Load(new MemoryStream(Encoding.UTF8.GetBytes(GoogleClientSecrets.Secrets))).Secrets
        //        }), "user", new TokenResponse { IdToken = request.IdToken });

        //        // Validate the credential and create a JWT token
        //        if (!string.IsNullOrEmpty(credential.UserId))
        //        {
        //            // Generate a JWT token
        //            var token = GenerateToken(credential.UserId);
        //            return new AuthenticationResult { Success = true, Token = token };
        //        }
        //        else
        //        {
        //            return new AuthenticationResult { Success = false, Errors = new List<string> { "Invalid IdToken" } };
        //        }


        //        //using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(request.IdToken)))
        //        //{
        //        //    var credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
        //        //        GoogleClientSecrets.Load(stream).Secrets,
        //        //        new[] { Google.Apis.Auth.OAuth2.GoogleAuthConsts.PlusLoginScope },
        //        //        "user",
        //        //        CancellationToken.None
        //        //    );

        //        //    // Validate the credential and create a JWT token
        //        //    if (credential != null && !string.IsNullOrEmpty(credential.UserId))
        //        //    {
        //        //        // Generate a JWT token
        //        //        var token = GenerateToken(credential.UserId);
        //        //        return new AuthenticationResult { Token = token };
        //        //    }
        //        //    else
        //        //    {
        //        //        return new AuthenticationResult { Errors = new List<string> { "Error message 1", "Error message 2" }  };
        //        //    }
        //        //}

        //        //var service = new Google.Apis.Plus.v1.PlusService(new Google.Apis.Services.BaseClientService.Initializer()
        //        //{
        //        //    HttpClientInitializer = credential,
        //        //    ApplicationName = "Your Application Name"
        //        //});

        //        //var profile = await service.People.Get("me").ExecuteAsync();
        //        //var user = new Usernew
        //        //{
        //        //    Email = profile.Emails?.FirstOrDefault()?.Value,
        //        //    FirstName = profile.Name?.GivenName,
        //        //    LastName = profile.Name?.FamilyName//,
        //        //    //ProfileImageUrl = profile.Image?.Url
        //        //};

        //        //// TODO: Check if user exists in your database and perform any necessary actions

        //        //var jwtToken = GenerateToken(user);
        //        //return new AuthenticationResult
        //        //{
        //        //    Success = true,
        //        //    Token = jwtToken
        //        //};
        //    }
        //    catch (Exception ex)
        //    {
        //        return new AuthenticationResult
        //        {
        //            Success = false,
        //            //ErrorMessage = new List<string> { ex.Message };
        //        };
        //    }
        //}


        //public async Task<AuthenticationResult> LoginWithFacebookAsync(LoginWithFacebookRequest request)
        //{
        //    // TODO: Implement login with Facebook logic
        //}

        public async Task<AuthenticationResult> ChangePasswordAsync(string email, ChangePasswordRequest request)
        {
            // TODO: Implement change password logic

            var user = await _userRepository.GetAsync(u => u.Email == email && u.PasswordHash == HashPassword(request.OldPassword));//.GetByEmailAsync(email);
            if (user == null)
            {
                return new AuthenticationResult { Success = false, Errors = new List<string> { "User not found" } };
            }

            //var passwordSalt = GeneratePasswordSalt();
            var passwordHash = HashPassword(request.NewPassword);//, passwordSalt);

            //user.PasswordSalt = passwordSalt;
            user.PasswordHash = passwordHash;

            await _userRepository.UpdateAsync(user);

            return new AuthenticationResult { Success = true };
        }

        public async Task ForgetPasswordAsync(ForgetPasswordRequest request)
        {
            // TODO: Implement forget password logic
        }

        //public async Task<AuthenticationResult> UpdateProfileAsync(string email, UpdateProfileRequest request)
        //{
        //    // TODO: Implement update profile logic
        //}




        //public async Task<bool> GetUserByEmailAsync(string email)
        //{
        //    return await _userRepository.ExistsAsync(u => u.Email == email);
        //}

        //public async Task<bool> GetUserByPhoneNumberAsync(string phoneNumber)
        //{
        //    return await _userRepository.ExistsAsync(u => u.PhoneNumber == phoneNumber);
        //}
        //public async Task GenerateAndSendEmailOtpAsync(string email)
        //{
        //    // Generate a random 6-digit OTP
        //    var otp = _random.Next(100000, 999999).ToString();

        //    // Save the OTP in the cache with a 30-minute expiry time
        //    await _cacheService.SetAsync($"EmailOtp:{email}", otp, TimeSpan.FromMinutes(30));

        //    // Send the OTP via email
        //    await _emailService.SendOtpEmailAsync(email, otp);
        //}

        //public async Task<UserDTO> CreateUserAsync(UserDTO userDTO)
        //{
        //    // Check if a user with the given email or phone number already exists
        //    var existingUserWithEmail = await GetUserByEmailAsync(userDTO.Email);
        //    var existingUserWithPhoneNumber = await GetUserByPhoneNumberAsync(userDTO.PhoneNumber);

        //    if (existingUserWithEmail != null)
        //    {
        //        // User with this email already exists
        //        throw new System.Exception("User with this email already exists.");
        //    }

        //    if (existingUserWithPhoneNumber != null)
        //    {
        //        // User with this phone number already exists
        //        throw new System.Exception("User with this phone number already exists.");
        //    }

        //    // Map DTO to Entity
        //    var user = _mapper.Map<User>(userDTO);
        //    user.Password = HashPassword(user.Password);
        //    user.Id = Guid.NewGuid().ToString();
        //    user.IsEmailVerified = false;
        //    user.IsMobileVerified = false;

        //    // Insert user into database
        //    await _userRepository.AddAsync(user);

        //    // Map Entity back to DTO and return
        //    return _mapper.Map<UserDTO>(user);
        //}

        //public async Task UpdateUserAsync(string id, UserDTO userDTO)
        //{

        //        var packagesnew = await _userRepository.GetAsync(id);

        //        if (packagesnew == null)
        //        {
        //            throw new Exception("Package not found.");
        //        }

        //        //_mapper.Map(packagesnewDTO, packagesnew);
        //        //await _packagesnewRepository.UpdateAsync(packagesnew);
        //        // Map DTO to Entity
        //        var user = _mapper.Map<User>(userDTO);

        //    // Update user in database
        //    //await _userRepository.UpdateAsync(u => u.Id == user.Id, user);
        //    await _userRepository.UpdateAsync( user);
        //}
        //private string HashPassword(string password)
        //{
        //    using (SHA256 sha256Hash = SHA256.Create())
        //    {
        //        // Convert the input string to a byte array and compute the hash.
        //        byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));

        //        // Convert byte array to a string
        //        StringBuilder builder = new StringBuilder();
        //        for (int i = 0; i < bytes.Length; i++)
        //        {
        //            builder.Append(bytes[i].ToString("x2"));
        //        }
        //        return builder.ToString();
        //    }
        //}

        //public async Task DeleteUserAsync(string id)
        //{
        //    var packagesnew = await _userRepository.GetAsync(id);

        //    if (packagesnew == null)
        //    {
        //        throw new Exception("Package not found.");
        //    }

        //    await _userRepository.DeleteAsync(id);
        //    // Delete user from database
        //    //await _userRepository.DeleteOneAsync(u => u.Id == id);
        //}

        ////public UserService(IUserRepository userRepository)
        ////{
        ////    _userRepository = userRepository;
        ////}

        ////public async Task RegisterUser(User user)
        ////{
        ////    // Perform any validation or business logic checks on the user object
        ////    // ...

        ////    // Save the user to the database
        ////    await _userRepository.AddUserAsync(user);
        ////}
        ////public async Task RegisterUserAsync(UserDTO userDto)
        ////{
        ////    var user = _mapper.Map<User>(userDto);
        ////    await _userRepository.AddOneAsync(user);
        ////}
        //public async Task RegisterUserAsync(UserDTO userDto)
        //{
        //    // Perform any validation or business logic checks on the user object
        //    // ...
        //    var user = _mapper.Map<User>(userDto);

        //    user.Id = Guid.NewGuid().ToString();
        //    user.IsEmailVerified = false;
        //    user.IsMobileVerified = false;
        //    // Check if the user with this email already exists
        //    var existingUser = await _userRepository.GetAsync(user.Email);
        //    if (existingUser != null)
        //    {
        //        throw new Exception("User with this email already exists");
        //    }

        //    // Save the user to the database
        //    await _userRepository.AddAsync(user);
        //}

        ////public async Task<User> LoginUser(string email, string password)
        ////{
        ////    // Retrieve the user from the database
        ////    var user = await _userRepository.GetUserByEmailAsync(email);

        ////    // Check if the user exists and if the password matches
        ////    if (user != null && user.Password == password)
        ////    {
        ////        return user;
        ////    }

        ////    // Return null if the user does not exist or if the password is incorrect
        ////    return null;
        ////}
        //public async Task<string> LoginUser(string email, string password)
        //{
        //    // Retrieve the user from the database
        //    User user = await _userRepository.GetAsync(e => e.Email == email);

        //    // Check if the user exists and if the password matches
        //    if (user == null || !user.Password.Equals(password))
        //    {
        //        throw new Exception("Invalid email or password");
        //    }

        //    // Create a JWT token for the authenticated user
        //    var tokenHandler = new JwtSecurityTokenHandler();
        //    var key = Encoding.ASCII.GetBytes("PRAFULCHAUHAN123");
        //    var tokenDescriptor = new SecurityTokenDescriptor
        //    {
        //        Subject = new ClaimsIdentity(new Claim[]
        //        {
        //    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        //    new Claim(ClaimTypes.Name, user.Email.ToString()),
        //    new Claim(ClaimTypes.Role, user.Role.ToString()),

        //        }),
        //        Expires = DateTime.UtcNow.AddDays(7),
        //        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
        //            SecurityAlgorithms.HmacSha256Signature)
        //    };
        //    var token = tokenHandler.CreateToken(tokenDescriptor);
        //    return tokenHandler.WriteToken(token);
        //}



        //public async Task<bool> SendEmailOTPAsync(string email)
        //{
        //    var user = await _userRepository.GetAsync(e => e.Email == email);

        //    if (user == null)
        //    {
        //        return false;
        //    }

        //    // Generate OTP logic
        //    var otp = 123456;

        //    // Send OTP via email logic
        //    var isSent = true;

        //    if (isSent)
        //    {
        //        user.EmailOTP = otp;
        //        user.EmailOTPExpiry = DateTime.Now.AddMinutes(10);

        //        await _userRepository.UpdateAsync(user);

        //        return true;
        //    }

        //    return false;
        //}

        //public async Task<bool> VerifyEmailOTPAsync(string email, int otp)
        //{
        //    var user = await _userRepository.GetAsync(e => e.Email == email);

        //    if (user == null || user.EmailOTP != otp || user.EmailOTPExpiry < DateTime.Now)
        //    {
        //        return false;
        //    }

        //    user.IsEmailVerified = true;

        //    await _userRepository.UpdateAsync(user);

        //    return true;
        //}

        //public async Task<bool> SendMobileOTPAsync(string mobile)
        //{
        //    var user = await _userRepository.GetAsync(e => e.PhoneNumber == mobile);

        //    if (user == null)
        //    {
        //        return false;
        //    }

        //    // Generate OTP logic
        //    var otp = 123456;

        //    // Send OTP via SMS logic
        //    var isSent = true;

        //    if (isSent)
        //    {
        //        user.MobileOTP = otp;
        //        user.MobileOTPExpiry = DateTime.Now.AddMinutes(10);

        //        await _userRepository.UpdateAsync(user);

        //        return true;
        //    }

        //    return false;
        //}
        //private string GenerateOTP()
        //{
        //    var random = new Random();
        //    return random.Next(100000, 999999).ToString();
        //}
        //private bool VerifyPassword(string enteredPassword, string hashedPassword)
        //{
        //    using (var hmac = new System.Security.Cryptography.HMACSHA512())
        //    {
        //        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(enteredPassword));
        //        var hashedInputPassword = Convert.ToBase64String(computedHash);

        //        return hashedPassword == hashedInputPassword;
        //    }
        //}
        //private async Task SendEmailAsync(string email, string subject, string message)
        //{
        //    var emailMessage = new MimeMessage();
        //    emailMessage.From.Add(new MailboxAddress("Your Company", "noreply@yourcompany.com"));
        //    emailMessage.To.Add(new MailboxAddress("", email));
        //    emailMessage.Subject = subject;
        //    emailMessage.Body = new TextPart("plain") { Text = message };

        //    //using (var client = new SmtpClient())
        //    //{
        //    //    client.LocalDomain = "yourcompany.com";
        //    //    await client.ConnectAsync("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
        //    //    await client.AuthenticateAsync("noreply@yourcompany.com", "yourpassword");
        //    //    await client.SendAsync(emailMessage);
        //    //    await client.DisconnectAsync(true);
        //    //}
        //}
        ////private bool VerifyPassword(string password, string hashedPassword)
        ////{
        ////    using (var hmac = new System.Security.Cryptography.HMACSHA512())
        ////    {
        ////        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        ////        for (int i = 0; i < computedHash.Length; i++)
        ////        {
        ////            if (computedHash[i] != hashedPassword[i]) return false;
        ////        }
        ////    }
        ////    return true;
        ////}

    }
}
