using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;
using SITConnect200600M.Models;
using SITConnect200600M.Services;

namespace SITConnect200600M.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class RegisterModel : PageModel
    {
        private readonly SignInManager<SITConnect200600MUser> _signInManager;
        private readonly UserManager<SITConnect200600MUser> _userManager;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;
        private readonly Microsoft.AspNetCore.Hosting.IWebHostEnvironment _env;
        private readonly reCAPTCHAv3 _reCaptchaService;
        private readonly IConfiguration _configuration;
        private readonly SITConnect200600MContext _dbContext;

        public RegisterModel(
            UserManager<SITConnect200600MUser> userManager,
            SignInManager<SITConnect200600MUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender,
            Microsoft.AspNetCore.Hosting.IWebHostEnvironment env,
            IConfiguration configuration,
            reCAPTCHAv3 reCaptchaService,
            SITConnect200600MContext dbContext)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _env = env;
            _configuration = configuration;
            _reCaptchaService = reCaptchaService;
            _dbContext = dbContext;
            
            // Secret for recaptcha
            reCaptchaKey = _configuration["reCaptchaKeyClientSide"];
        }

        public string reCaptchaKey { get; set; }
        
        [BindProperty] public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        private static readonly string Today = DateTime.Now.ToShortDateString();

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public class InputModel
        {
            [RegularExpression(@"^[a-zA-Z]+$", ErrorMessage = "Only letters are allowed.")]
            [Required(ErrorMessage = "First name is required.")]
            [Display(Name = "First name")]
            public string FirstName { get; set; }

            [RegularExpression(@"^[a-zA-Z]+$", ErrorMessage = "Only letters are allow.")]
            [Required(ErrorMessage = "Last name is required.")]
            [Display(Name = "Last Name")]
            public string LastName { get; set; }

            [Required(ErrorMessage = "Email field is required.")]
            [EmailAddress(ErrorMessage = "This is not a valid email address.")]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required(ErrorMessage = "Password field is required")]
            [StringLength(100, ErrorMessage = "Password must be at least {2} characters long.", MinimumLength = 12)]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "Password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }

            [Required(ErrorMessage = "Credit card number is required")]
            /*
            [CardNumber(ErrorMessage = "This is not a valid credit card number.")]
            */
            [CreditCard(ErrorMessage = "This is not a valid credit card number.")]
            public string CardNumber { get; set; }

            [Required(ErrorMessage = "Date of birth is required.")]
            [DOBRange(ErrorMessage = "Date of birth must be at least 01/01/1900 and cannot be set in the future.")]
            [DataType(DataType.Date)]
            public DateTime DateOfBirth { get; set; }

            [Required(ErrorMessage = "The profile photo field is required.")]
            [Image(ErrorMessage = "Uploaded file is not a valid image.")]
            public IFormFile ProfilePhoto { get; set; }

            [Required] public string Token { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (User.Identity.IsAuthenticated)
            {
                Response.Redirect("/");
            }

            ReturnUrl = returnUrl;
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            var reCaptchaResult = _reCaptchaService.TokenVerify(Input.Token);
            if (!reCaptchaResult.Result.IsSuccess || reCaptchaResult.Result.Score <= 0.8)
            {
                ModelState.AddModelError(string.Empty, "Invalid captcha response, please try again.");
                return Page();
            }

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            if (ModelState.IsValid)
            {
                // Username field is compulsory, so I just put email as username
                // Encrypt credit card number here
                var encryptedCreditCard =
                    CreditCardCryptography.EncryptStringAes(Input.CardNumber.Replace("-", "").Replace(" ", ""),
                        _configuration["AESKey"]);

                var user = new SITConnect200600MUser
                {
                    UserName = Input.Email,
                    Email = Input.Email,
                    FirstName = Input.FirstName,
                    LastName = Input.LastName,
                    CardNumber = encryptedCreditCard,
                    DateOfBirth = Input.DateOfBirth,
                    TwoFactorEnabled = true
                };

                // Inserting user entry into database
                var result = await _userManager.CreateAsync(user, Input.Password);
                if (result.Succeeded)
                {
                    // Saving the profile image of the user into wwwroot upon successful user creation
                    var fileName = $"{user.Id}.png";
                    var filePath = Path.Combine(_env.WebRootPath, "profile", fileName);
                    using (var fileSteam = new FileStream(filePath, FileMode.Create))
                    {
                        await Input.ProfilePhoto.CopyToAsync(fileSteam);
                    }

                    _logger.LogInformation("User profile image uploaded successfully");


                    // Password logs to save password history
                    var userInformation = _dbContext.Users.Single(entry => entry.Email == user.Email);
                    var passwordLog = new PasswordHistory
                    {
                        UserId = userInformation.Id,
                        Password1 = userInformation.PasswordHash,
                        Password1Timestamp = DateTime.Now,
                        Password2 = userInformation.PasswordHash,
                        Password2Timestamp = DateTime.Now
                    };

                    _dbContext.PasswordHistoryLogs.Add(passwordLog);
                    await _dbContext.SaveChangesAsync();


                    // Email verification 
                    _logger.LogInformation("User created a new account with password.");
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callbackUrl = Url.Page(
                        "/Account/ConfirmEmail",
                        pageHandler: null,
                        values: new {area = "Identity", userId = user.Id, code = code, returnUrl = returnUrl},
                        protocol: Request.Scheme);

                    await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                        $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                    if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    {
                        return RedirectToPage("RegisterConfirmation", new {email = Input.Email, returnUrl = returnUrl});
                    }
                    else
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return LocalRedirect(returnUrl);
                    }
                }

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty,
                        error.Description.StartsWith("User name")
                            ? error.Description.Replace("User name", "Email")
                            : error.Description);
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
    }
}