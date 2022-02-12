using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;
using SITConnect200600M.Models;
using SITConnect200600M.Services;

namespace SITConnect200600M.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginWith2faModel : PageModel
    {
        private readonly SignInManager<SITConnect200600MUser> _signInManager;
        private readonly ILogger<LoginWith2faModel> _logger;
        private readonly UserManager<SITConnect200600MUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly SITConnect200600MContext _dbContext;
        private readonly IConfiguration _configuration;
        private readonly reCAPTCHAv3 _reCaptchaService;

        public LoginWith2faModel(
            SignInManager<SITConnect200600MUser> signInManager,
            ILogger<LoginWith2faModel> logger,
            UserManager<SITConnect200600MUser> userManager,
            IEmailSender emailSender,
            SITConnect200600MContext dbContext,
            IConfiguration configuration,
            reCAPTCHAv3 reCaptchaService)
        {
            _signInManager = signInManager;
            _logger = logger;
            _userManager = userManager;
            _emailSender = emailSender;
            _dbContext = dbContext;
            _configuration = configuration;
            _reCaptchaService = reCaptchaService;


            // Secret for recaptcha
            reCaptchaKey = _configuration["reCaptchaKeyClientSide"];
        }

        public string reCaptchaKey { get; set; }

        [BindProperty] public InputModel Input { get; set; }

        public bool RememberMe { get; set; }

        public string ReturnUrl { get; set; }

        public class InputModel
        {
            [Required]
            [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.",
                MinimumLength = 6)]
            [DataType(DataType.Text)]
            [Display(Name = "Authenticator code")]
            public string TwoFactorCode { get; set; }

            [Display(Name = "Remember this machine")]
            public bool RememberMachine { get; set; }

            [Required] public string Token { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(bool rememberMe, string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var currentUser = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (currentUser == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            // Creating 2FA token and sending it
            var token = await _userManager.GenerateTwoFactorTokenAsync(currentUser, "Email");
            await _emailSender.SendEmailAsync(currentUser.Email, "Two-Factor Authentication", token);

            ReturnUrl = returnUrl;
            RememberMe = rememberMe;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(bool rememberMe, string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            var reCaptchaResult = _reCaptchaService.TokenVerify(Input.Token);
            if (!reCaptchaResult.Result.IsSuccess || reCaptchaResult.Result.Score <= 0.8)
            {
                ModelState.AddModelError(string.Empty, "Invalid captcha response, please try again.");
                return Page();
            }

            if (!ModelState.IsValid)
            {
                return Page();
            }

            returnUrl = returnUrl ?? Url.Content("~/");

            var currentUser = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (currentUser == null)
            {
                throw new InvalidOperationException($"Unable to load two-factor authentication user.");
            }

            var result =
                await _signInManager.TwoFactorSignInAsync("Email", Input.TwoFactorCode, false, Input.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User with ID '{UserId}' logged in with 2fa.", currentUser.Id);

                // Logging that the user has successfully logged in
                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = currentUser.Id,
                    Action = "LoginSuccess",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                });

                await _dbContext.SaveChangesAsync();
                return LocalRedirect(returnUrl);
            }
            else if (result.IsLockedOut)
            {
                // Logging that the user has successfully logged in
                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = currentUser.Id,
                    Action = "LoginFailed",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                    Reason = "Account lockout on user."
                });

                await _dbContext.SaveChangesAsync();

                _logger.LogWarning("User with ID '{UserId}' account locked out.", currentUser.Id);
                return RedirectToPage("./Lockout");
            }
            else
            {
                // Failing 2FA
                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = currentUser.Id,
                    Action = "LoginFailed",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                    Reason = "Invalid 2FA token."
                });

                await _dbContext.SaveChangesAsync();

                _logger.LogWarning("Invalid authenticator code entered for user with ID '{UserId}'.", currentUser.Id);
                ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                return Page();
            }
        }
    }
}