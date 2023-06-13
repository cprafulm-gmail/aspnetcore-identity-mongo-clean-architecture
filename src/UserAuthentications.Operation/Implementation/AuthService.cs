using AutoMapper;
using UserAuthentications.Core.Entities;
using UserAuthentications.Infrastructure.Persistence;
using UserAuthentications.Operation.Abstractions;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Plus.v1;
using Google.Apis.Services;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using UserAuthentications.Shared.DTOs;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Options;
using MimeKit;
using MimeKit.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AspNetCore.Identity.MongoDbCore.Models;
using UserAuthentications.Core.Entities.Identity;

using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Identity;
using Org.BouncyCastle.Asn1.Ocsp;
using Microsoft.AspNetCore.Http;
using static Google.Apis.Auth.OAuth2.Web.AuthorizationCodeWebApp;
using System.Net.Http;
using SendGrid.Helpers.Mail;

namespace UserAuthentications.Operation.Implementation
{
    //public static class GoogleAuthConsts
    //{
    //    public const string PlusLoginScope = "https://www.googleapis.com/auth/plus.login";
    //}
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IMapper _mapper;
        //private readonly IEmailService _emailService;
        private readonly ICacheService _cacheService;
        private readonly Random _random = new Random();
        private readonly RoleManager<ApplicationRole> _roleManager;
        //private readonly ISmsService _smsService;
        //private readonly IJwtService _jwtService;

        public AuthService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IMapper mapper, IMongoRepository<Usernew> userRepository,  ICacheService cacheService, RoleManager<ApplicationRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _mapper = mapper;
            //_emailService = emailService;
            _cacheService = cacheService;
            _roleManager = roleManager;
        }
        public async Task<AuthenticationResult> AuthenticateAsync(string email, string password)
        {
            // Check if user with same email exists
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return null;
            }

            // Check if user password is valid
            var result = await _signInManager.CheckPasswordSignInAsync(user, password, false);
            if (!result.Succeeded)
            {
                return null;
            }

            var newUser = new ApplicationUser
            {
                Email = user.Email,
                UserName = user.Email,
                userId = user.Id
            };
            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateToken(newUser),
                //User = newUser
            };
        }

        public async Task<AuthenticationResult> RegisterAsync(UserRegistrationRequest request)
        {
            // Check if the email is already taken
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };
            }

            var newUser = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName
            };

            // Attempt to create the user with the provided password
            var result = await _userManager.CreateAsync(newUser, request.PasswordHash);
            if (!result.Succeeded)
            {
                return new AuthenticationResult { Errors = result.Errors.Select(e => e.Description) };
            }

            //// If user is created successfully, sign in the user and return a JWT token
            //var signInResult = await _signInManager.PasswordSignInAsync(newUser.Email, request.PasswordHash, false, false);
            //if (!signInResult.Succeeded)
            //{
            //    return new AuthenticationResult { Errors = new[] { "Unable to sign in" } };
            //}
            // Check if the "USER" role exists
            var userRole = await _roleManager.FindByNameAsync("USER");
            if (userRole == null)
            {
                // Create the "USER" role if it doesn't exist
                var role = new ApplicationRole { Name = "USER" };
                await _roleManager.CreateAsync(role);
                userRole = role;
            }

            // Add the user to the "USER" role
            await _userManager.AddToRoleAsync(newUser, userRole.Name);

            var code = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);


            //await _signInManager.CheckPasswordSignInAsync(newUser, request.PasswordHash, false);

            if (!result.Succeeded)
            {
                return new AuthenticationResult { Errors = result.Errors.Select(e => e.Description) };
            }
            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateToken(newUser),
                //User = newUser
            };
        }

        public async Task<AuthenticationResult> UpdateProfileAsync(string userId, UpdateProfileRequest request)
        {
            var user = await _userManager.FindByIdAsync(userId);
            // Check if user with email exists
            //var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return null;
            }

            // Update user properties
            user.FirstName = request.FirstName;
            user.LastName = request.LastName;
            user.PhoneNumber = request.PhoneNumber;
            user.Birthdate = request.Birthdate;
            user.Gender = request.Gender;

            // Update user in the database
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return new AuthenticationResult { Errors = result.Errors.Select(e => e.Description) };
            }

            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateToken(user)
            };
        }
        public async Task<AuthenticationResult> LoginWithFacebookAsync(LoginWithFacebookRequest dto)
        {
            var fbAppId = "";//_configuration["Facebook:AppId"];
            var fbAppSecret = "";//_configuration["Facebook:AppSecret"];

            // Request access token from Facebook using the OAuth2 flow
            var fbTokenUrl = $"https://graph.facebook.com/v12.0/oauth/access_token?client_id={fbAppId}&client_secret={fbAppSecret}&redirect_uri={dto.RedirectUri}&code={dto.Code}";
            using var httpClient = new HttpClient();
            var fbTokenResponse = await httpClient.GetAsync(fbTokenUrl);
            if (!fbTokenResponse.IsSuccessStatusCode)
            {
                //return AuthResult.Failed("Failed to obtain Facebook access token.");
                return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };
            }
            var fbTokenJson = await fbTokenResponse.Content.ReadAsStringAsync();
            var fbTokenObj = JsonConvert.DeserializeObject<LoginWithFacebookRequest>(fbTokenJson);

            // Request user profile data from Facebook using the obtained access token
            var fbProfileUrl = $"https://graph.facebook.com/v12.0/me?fields=id,email,first_name,last_name&access_token={fbTokenObj.AccessToken}";
            var fbProfileResponse = await httpClient.GetAsync(fbProfileUrl);
            if (!fbProfileResponse.IsSuccessStatusCode)
            {
                //return AuthResult.Failed("Failed to obtain Facebook user profile.");
                return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };

            }
            var fbProfileJson = await fbProfileResponse.Content.ReadAsStringAsync();
            var fbProfileObj = JsonConvert.DeserializeObject<LoginWithFacebookRequest>(fbProfileJson);

            // Check if the user already exists
            var user = await _userManager.FindByEmailAsync(fbProfileObj.Email);
            if (user == null)
            {
                // Create a new user if they don't exist
                user = new ApplicationUser
                {
                    Email = fbProfileObj.Email,
                    FirstName = fbProfileObj.FirstName,
                    LastName = fbProfileObj.LastName,
                    UserName = fbProfileObj.Email,
                };
                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    //return AuthResult.Failed("Failed to create user.");
                    return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };
                }
            }

            // Sign in the user
            var signInResult = await _signInManager.PasswordSignInAsync(user.UserName, fbAppId, isPersistent: false, lockoutOnFailure: false);
            if (!signInResult.Succeeded)
            {
                return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };
                //return AuthResult.Failed("Failed to sign in user.");
            }


            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateToken(user)
            };
            // Generate JWT token for the user
            //var jwt = GenerateJwt(user);

            //return AuthResult.Success(jwt);
        }


        public async Task<AuthenticationResult> LoginWithGoogleAsync(GoogleProfile dto)
        {
            var googleClientId = "977119073212-86broul2astpqvc50qsrvjkgurslmaio.apps.googleusercontent.com";//; _configuration["Google:ClientId"];
            var googleClientSecret = "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";// _configuration["Google:ClientSecret"];

            // Request access token from Google using the OAuth2 flow
            var googleTokenUrl = "https://oauth2.googleapis.com/token";
            var googleTokenRequestContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("code", dto.Code),
                new KeyValuePair<string, string>("client_id", "977119073212-86broul2astpqvc50qsrvjkgurslmaio.apps.googleusercontent.com"),
                new KeyValuePair<string, string>("client_secret", "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"),
                new KeyValuePair<string, string>("redirect_uri", "https://localhost:7006/api/UserAuthentication/login/google/signin-google"),
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
            });
            using var httpClient = new HttpClient();
            var googleTokenResponse = await httpClient.PostAsync(googleTokenUrl, googleTokenRequestContent);
            if (!googleTokenResponse.IsSuccessStatusCode)
            {
                return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };
                //return AuthResult.Failed("Failed to obtain Google access token.");
            }
            var googleTokenJson = await googleTokenResponse.Content.ReadAsStringAsync();
        var googleTokenObj = JsonConvert.DeserializeObject<GoogleAccessTokenDto>(googleTokenJson);

        // Request user profile data from Google using the obtained access token
        var googleProfileUrl = $"https://www.googleapis.com/oauth2/v1/userinfo?access_token={googleTokenObj.AccessToken}";
        var googleProfileResponse = await httpClient.GetAsync(googleProfileUrl);
        if (!googleProfileResponse.IsSuccessStatusCode)
        {
                        return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };
                        //return AuthResult.Failed("Failed to obtain Google user profile.");
                    }
                    var googleProfileJson = await googleProfileResponse.Content.ReadAsStringAsync();
        var googleProfileObj = JsonConvert.DeserializeObject<GoogleProfile>(googleProfileJson);

        // Check if the user already exists
        var user = await _userManager.FindByEmailAsync(googleProfileObj.Email);
        if (user == null)
        {
            // Create a new user if they don't exist
            user = new ApplicationUser
            {
                Email = googleProfileObj.Email,
                FirstName = googleProfileObj.GivenName,
                LastName = googleProfileObj.FamilyName,
                UserName = googleProfileObj.Email,
            };
            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                            return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };
                            //return AuthResult.Failed("Failed to create user.");
                        }
                    }

        // Sign in the user
        var signInResult = await _signInManager.PasswordSignInAsync(user.UserName, googleClientId, isPersistent: false, lockoutOnFailure: false);
        if (!signInResult.Succeeded)
        {
                        return new AuthenticationResult { Errors = new[] { "Email address is already taken" } };
                        //return AuthResult.Failed("Failed to sign in user.");
                    }


                    return new AuthenticationResult
                    {
                        Success = true,
                        Token = GenerateToken(user)
                    };
                    // Generate JWT token for the user
            //var jwt = GenerateJwt(user);

            //return AuthResult.Success(jwt);
        }
        public async Task<AuthenticationResult> GetUserByEmailAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return null;
            }

            var newUser = new ApplicationUser
            {
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName
            };

            return new AuthenticationResult
            {
                Success = true,
                AppUser = user
            };
        }
        public async Task<AuthenticationResult> AddCoTravelerAsync(string userId, CoTravellerRequest request)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ArgumentException("User not found.");
            }

            var coTravellerExist = user.CoTravellers.FirstOrDefault(c => c.Email == request.Email);
            if (coTravellerExist != null)
            {
                return new AuthenticationResult { Errors = new[] { "Co-traveller already exist" } };
                //throw new ArgumentException("Co-traveler not found.");
            }


            var coTraveller = new CoTraveller
            {
                Id = ObjectId.GenerateNewId().ToString(),
                FirstName = request.FirstName,
                LastName = request.LastName,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                Gender = request.Gender
            };
            user.CoTravellers.Add(coTraveller);
            var result  = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return new AuthenticationResult { Errors = result.Errors.Select(e => e.Description) };
            }

            return new AuthenticationResult
            {
                Success = true,
            };
        }

        public async Task<List<CoTraveller>> GetCoTravelersAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ArgumentException("User not found.");
            }

            return user.CoTravellers.ToList();
        }
        public async Task<AuthenticationResult> UpdateCoTravellerAsync(string userId, CoTravellerRequest coTraveller)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ArgumentException("User not found.");
            }

            // Find the specific CoTraveller entity to update
            var coTravellerToUpdate = user.CoTravellers.FirstOrDefault(ct => ct.Id == coTraveller.Id);
            if (coTravellerToUpdate == null)
            {
                throw new ArgumentException("CoTraveller not found.");
            }

            // Update the properties of the CoTraveller entity
            coTravellerToUpdate.FirstName = coTraveller.FirstName;
            coTravellerToUpdate.LastName = coTraveller.LastName;
            coTravellerToUpdate.Email = coTraveller.Email;
            coTravellerToUpdate.PhoneNumber = coTraveller.PhoneNumber;
            coTravellerToUpdate.Gender = coTraveller.Gender;

            // Call SaveChangesAsync to persist the changes to the database
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return new AuthenticationResult { Errors = result.Errors.Select(e => e.Description) };
            }

            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateToken(user)
            };
        }

        public async Task<AuthenticationResult> RemoveCoTravelerAsync(string userId, string coTravellerId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new ArgumentException("User not found.");
            }

            var coTravellerToRemove = user.CoTravellers.FirstOrDefault(c => c.Id == coTravellerId);
            if (coTravellerToRemove == null)
            {
                throw new ArgumentException("Co-traveler not found.");
            }

            user.CoTravellers.Remove(coTravellerToRemove);
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return new AuthenticationResult { Errors = result.Errors.Select(e => e.Description) };
            }

            return new AuthenticationResult
            {
                Success = true,
                Token = GenerateToken(user)
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

        private string GenerateToken(ApplicationUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("PRAFULCHAUHAN123");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    //new Claim(ClaimTypes.Name, user.Id),
                    new Claim(ClaimTypes.Email, user.Email)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)// HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var sdfdsf = tokenHandler.WriteToken(token);
            //return tokenHandler.WriteToken(token);



            // Define the claims for the token
            var claims = new[]
            {
            new Claim(ClaimTypes.Email, user.Email),
        new Claim(ClaimTypes.NameIdentifier, user.userId.ToString())
    };

            // Create the signing key
            var key1 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("PRAFULCHAUHAN123"));

            // Create the signing credentials
            var creds = new SigningCredentials(key1, SecurityAlgorithms.HmacSha256);

            // Create the JWT token
            var token1 = new JwtSecurityToken(
                issuer: "https://localhost:7006/",
                audience: "myapp",
                claims: claims,
                expires: DateTime.Now.AddMinutes(300),
                signingCredentials: creds
            );

            // Serialize the JWT token
            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token1);

            var sfsdfds =  jwtToken;

            return sfsdfds;// sdfdsf;
        }



    }
}
