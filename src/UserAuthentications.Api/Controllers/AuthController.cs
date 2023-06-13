using UserAuthentications.Core.Entities;
using UserAuthentications.Operation.Abstractions;
using UserAuthentications.Operation.Implementation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace UserAuthentications.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        //private readonly IEmailSender _emailSender;
        //private readonly ISmsSender _smsSender;
        private readonly ILogger _logger;
        private readonly IUrlHelperFactory _urlHelperFactory;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly IAuthService _authService;


        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            //IEmailSender emailSender,
            ILoggerFactory loggerFactory,
            IUrlHelperFactory urlHelperFactory, RoleManager<ApplicationRole> roleManager, IAuthService authService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            //_emailSender = emailSender;
            _logger = loggerFactory.CreateLogger<AuthController>();
            _urlHelperFactory = urlHelperFactory;
            _roleManager = roleManager;
            _authService = authService;
        }


        [HttpPut("update-profile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfileAsync([FromBody] UpdateProfileRequest request)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Unable to get user information");
            }

            var result = await _authService.UpdateProfileAsync(userId, request);
            if (!result.Success)
            {
                return BadRequest(result.Errors);
            }

            return Ok(new { result.User });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync(UserRegistrationRequest request)
        {


            var token = await _authService.RegisterAsync(request);
            if (token == null)
            {
                return BadRequest(new { errors = "Invalid login attempt" });
            }

            return Ok(new { token });
            // Check if user with same email already exists
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return BadRequest(new { errors = "A user with this email already exists" });
            }

            // Create new user and send email confirmation
            var user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName
            };
            //var user = new ApplicationUser { UserName = request.Email, Email = request.Email };
            var result = await _userManager.CreateAsync(user, request.PasswordHash);
            if (result.Succeeded)
            {
                // Create the role manager
                var roleManager = HttpContext.RequestServices.GetRequiredService<RoleManager<ApplicationRole>>();

                // Check if the "USER" role exists
                var roleExists = await roleManager.RoleExistsAsync("USER");

                if (!roleExists)
                {
                    // Create the "USER" role if it doesn't exist
                    var role = new ApplicationRole { Name = "USER" };
                    await roleManager.CreateAsync(role);
                }

                // Add the user to the "USER" role
                var result1 = await _userManager.AddToRoleAsync(user, "USER");

                if (!result1.Succeeded)
                {
                    // Handle the error
                }
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                //var urlHelper = _urlHelperFactory.GetUrlHelper(ControllerContext);
                //var callbackUrl = urlHelper.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, HttpContext.Request.Scheme);
                //await _emailSender.SendEmailAsync(request.Email, "Confirm your account", $"Please confirm your account by clicking this link: <a href=\"{callbackUrl}\">link</a>");                //var urlHelper = _urlHelperFactory.GetUrlHelper(ControllerContext);
                //var callbackUrl = urlHelper.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, HttpContext.Request.Scheme);
                //await _emailSender.SendEmailAsync(request.Email, "Confirm your account", $"Please confirm your account by clicking this link: <a href=\"{callbackUrl}\">link</a>");

                // Send mobile confirmation
                // var smsMessage = $"Please confirm your account by entering this code: {confirmationCode}";
                // await _smsSender.SendSmsAsync(request.PhoneNumber, smsMessage);

                // Sign in the new user
                await _signInManager.CheckPasswordSignInAsync(user, request.PasswordHash, false);
                //var dgdf =  result0.Succeeded;
                //var result1 = await _signInManager.PasswordSignInAsync(request.Email, request.PasswordHash, true, false);
                //var sdsd = result1.Succeeded;
                //await _signInManager.SignInAsync(user, isPersistent: false);

                return Ok(new { token = "SDfdsfds" });
            }
            else
            {
                return BadRequest(new { errors = result.Errors });
            }
        }

        [Authorize]
        [HttpGet("user")]
        public async Task<IActionResult> GetUser()
        {

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Unable to get user information");
            }

            var result = await _authService.GetUserByEmailAsync(userId);
            if (!result.Success)
            {
                return BadRequest(result.Errors);
            }

            return Ok(new { result.AppUser });

            // Return the user details
            //return Ok(user);
        }
        [Authorize]
        [HttpPost("cotravelers")]
        public async Task<IActionResult> AddCoTraveler([FromBody] CoTravellerRequest coTraveller)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            await _authService.AddCoTravelerAsync(userId, coTraveller);
            return Ok();
        }


        [Authorize]
        [HttpPost("update-cotravelers")]
        public async Task<IActionResult> UpdateCoTraveler([FromBody] CoTravellerRequest coTraveller)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            await _authService.UpdateCoTravellerAsync(userId, coTraveller);
            return Ok();
        }
        [Authorize]
        [HttpGet("cotravelers")]
        public async Task<IActionResult> GetCoTravelers()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var coTravelers = await _authService.GetCoTravelersAsync(userId);
            return Ok(coTravelers);
        }
        [Authorize]
        [HttpDelete("coTravellers/{coTravellerId}")]
        public async Task<IActionResult> RemoveCoTraveler(string coTravellerId)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            // Call UserRepository to remove co-traveler
            await _authService.RemoveCoTravelerAsync(userId, coTravellerId);
            return Ok();
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginAsync(UserLoginRequest request)
        {

            var data = await _authService.AuthenticateAsync(request.Email, request.Password);
            if (data == null)
            {
                return BadRequest(new { errors = "Invalid login attempt" });
            }

            Response.Headers.Add("Authorization", $"Bearer {data.Token}");

            return Ok(new { data });
        }
    }
}
