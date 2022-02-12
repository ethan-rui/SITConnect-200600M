using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;
using SITConnect200600M.Models;
using SITConnect200600M.Services;

namespace SITConnect200600M.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly UserManager<SITConnect200600MUser> _userManager;
        private readonly SignInManager<SITConnect200600MUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly reCAPTCHAv3 _reCaptchaService;
        private readonly SITConnect200600MContext _dbContext;
        private readonly IConfiguration _configuration;

        public LoginModel(SignInManager<SITConnect200600MUser> signInManager,
            ILogger<LoginModel> logger,
            UserManager<SITConnect200600MUser> userManager,
            reCAPTCHAv3 reCaptchaService,
            SITConnect200600MContext dbContext,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _reCaptchaService = reCaptchaService;
            _dbContext = dbContext;
            _configuration = configuration;

            // Secret for recaptcha
            reCaptchaKey = _configuration["reCaptchaKeyClientSide"];
            lockoutDuration = _configuration.GetValue<int>("AccountLockoutDurationSeconds");
        }

        [BindProperty] public InputModel Input { get; set; }

        public string reCaptchaKey { get; set; }
        public int lockoutDuration { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData] public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "The email field is required.")]
            [EmailAddress(ErrorMessage = "This is not a valid email address")]
            public string Email { get; set; }

            [Required(ErrorMessage = "The password field is required.")]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")] public bool RememberMe { get; set; }

            [Required] public string Token { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            Console.WriteLine(User.Identity.IsAuthenticated);
            // Redirect if logged in
            if (User.Identity.IsAuthenticated)
            {
                Response.Redirect("/");
            }

            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl = returnUrl ?? Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
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

            if (!ModelState.IsValid) return Page();

            // Failed IP attempts from the past 5 minutes
            // This only lock out the client if their credientials is invalid

            var failedAttemptsByIPCount = _dbContext.AuditLogs.Count(entry =>
                entry.IP == HttpContext.Connection.RemoteIpAddress.ToString() &&
                entry.TimeStamp >= DateTime.Now.AddSeconds(-lockoutDuration) &&
                entry.Reason == "Invalid credentials combination."
            );

            if (failedAttemptsByIPCount >= 3)
            {
                ModelState.AddModelError(string.Empty,
                    $"Account has been locked out, please try again in {lockoutDuration} seconds.");
                return Page();
            }


            // Checking of their credentials
            SITConnect200600MUser currentUser;
            try
            {
                // This covers the null exception if there not users
                currentUser = _dbContext.Users.Single(user => user.Email == Input.Email);
            }
            catch (Exception e)
            {
                await InvalidCredentials("");
                return Page();
            }

            // Checking if the current user's email is verified 
            if (!currentUser.EmailConfirmed)
            {
                _logger.LogInformation("User email not confirmed");
                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = currentUser.Id,
                    Action = "LoginFailed",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                    Reason = "Email not verified"
                });
                await _dbContext.SaveChangesAsync();
                ModelState.AddModelError(string.Empty, "You need to verify your email before you can login.");
                return Page();
            }

            // Everything here will run if the
            // user exists
            // their email is verified 
            // no lockouts on their IP

            var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe,
                lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");

                // Login successful 
                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = currentUser.Id,
                    Action = "LoginSuccess",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString()
                });
                await _dbContext.SaveChangesAsync();

                return LocalRedirect(returnUrl);
            }
            else if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new {ReturnUrl = returnUrl, RememberMe = Input.RememberMe});
            }
            else if (result.IsLockedOut)
            {
                await AccountLockedOut(currentUser.Id);
                return Page();
            }
            else
            {
                await InvalidCredentials(currentUser.Id);
                return Page();
            }

            // If we got this far, something failed, redisplay form
        }


        private async Task AccountLockedOut(string userId)
        {
            _dbContext.AuditLogs.Add(new AuditLog
            {
                UserId = userId,
                Action = "LoginFailed",
                IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                Reason = "Account lockout on user."
            });

            await _dbContext.SaveChangesAsync();

            _logger.LogWarning("User account locked out.");
            ModelState.AddModelError(string.Empty,
                $"Account has been locked out, please try again in {lockoutDuration} seconds.");
        }


        private async Task InvalidCredentials(string userId)
        {
            // Wrong credentials 
            _dbContext.AuditLogs.Add(new AuditLog
            {
                UserId = userId,
                Action = "LoginFailed",
                IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                Reason = "Invalid credentials combination."
            });

            await _dbContext.SaveChangesAsync();
            _logger.LogWarning("Invalid credentials.");

            var failedAttemptsByIPCount = _dbContext.AuditLogs.Count(entry =>
                entry.IP == HttpContext.Connection.RemoteIpAddress.ToString() &&
                entry.TimeStamp >= DateTime.Now.AddSeconds(-lockoutDuration) &&
                entry.Reason == "Invalid credentials combination."
            );

            if (failedAttemptsByIPCount >= 3)
            {
                ModelState.AddModelError(string.Empty,
                    $"Account has been locked out, please try again in {lockoutDuration} seconds.");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt, please try again.");
            }
        }
    }
}