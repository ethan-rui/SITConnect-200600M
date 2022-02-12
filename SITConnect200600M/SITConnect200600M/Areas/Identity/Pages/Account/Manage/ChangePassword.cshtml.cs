using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;
using SITConnect200600M.Models;
using SITConnect200600M.Services;

namespace SITConnect200600M.Areas.Identity.Pages.Account.Manage
{
    [AllowAnonymous]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<SITConnect200600MUser> _userManager;
        private readonly SignInManager<SITConnect200600MUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;
        private readonly SITConnect200600MContext _dbContext;
        private readonly PasswordUtils _pwdUtils;
        private readonly IConfiguration _configuration;
        private readonly reCAPTCHAv3 _reCaptchaService;

        public ChangePasswordModel(
            UserManager<SITConnect200600MUser> userManager,
            SignInManager<SITConnect200600MUser> signInManager,
            ILogger<ChangePasswordModel> logger,
            SITConnect200600MContext dbContext,
            PasswordUtils pwdUtils,
            IConfiguration configuration,
            reCAPTCHAv3 reCaptchaService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _dbContext = dbContext;
            _pwdUtils = pwdUtils;
            _configuration = configuration;
            _reCaptchaService = reCaptchaService;

            // Secret for recaptcha
            reCaptchaKey = _configuration["reCaptchaKeyClientSide"];

            // Password age
            passwordMinAge = _configuration.GetValue<int>("PasswordMinAgeSeconds");
            passwordMaxAge = _configuration.GetValue<int>("PasswordMaxAgeSeconds");
        }

        public string reCaptchaKey { get; set; }
        public int passwordMinAge { get; set; }
        public int passwordMaxAge { get; set; }


        [BindProperty] public InputModel Input { get; set; }
        [TempData] public string StatusMessage { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Current password is required.")]
            [Display(Name = "Current password")]
            public string OldPassword { get; set; }

            [Required(ErrorMessage = "New password is required.")]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.",
                MinimumLength = 12)]
            [Display(Name = "New password")]
            public string NewPassword { get; set; }

            [Display(Name = "Confirm new password")]
            [Compare("NewPassword", ErrorMessage = "New password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }

            [Required] public string Token { get; set; }
        }

        [BindProperty] public bool PasswordChangeble { get; set; } = true;
        [BindProperty] public bool PasswordExpired { get; set; } = false;

        public async Task<IActionResult> OnGetAsync()
        {
            // User is not authenticated
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return StatusCode(401);
            }

            // Get most recent password change
            var mostRecentPasswordChange = _pwdUtils.GetMostRecentPasswordChange(user.Id);

            // Most recent password change DateTime
            var passwordAge = _pwdUtils.TimeDifferenceInSeconds(mostRecentPasswordChange);

            _logger.LogInformation($"Password age for user is {passwordAge}");
            _logger.LogInformation($"Current DateTime: {DateTime.Now}");
            _logger.LogInformation($"Most recent password change DateTIme: {mostRecentPasswordChange}");

            // Password max age
            if (passwordAge >= passwordMaxAge)
            {
                StatusMessage = "Your current password has expired, please set a new password.";
                PasswordExpired = true;
                return Page();
            }

            // Password min age
            if (passwordAge <= passwordMinAge)
            {
                PasswordChangeble = false;
                PasswordExpired = false;
                if (StatusMessage != "Password has been changed.")
                {
                    ModelState.AddModelError(string.Empty,
                        "You recently just changed your password, please try again in 30 seconds.");
                }

                return Page();
            }

            PasswordChangeble = true;
            PasswordExpired = false;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            // If user is not authenticated
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return StatusCode(401);
            }

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

            // Get password logs for the current user
            var passwordHistory = _dbContext.PasswordHistoryLogs.Single(entry => entry.UserId == user.Id);

            // Get most recent password change
            var mostRecentPasswordChange = _pwdUtils.GetMostRecentPasswordChange(user.Id);

            // Most recent password change DateTime
            var passwordAge = _pwdUtils.TimeDifferenceInSeconds(mostRecentPasswordChange);

            _logger.LogInformation($"Password age for current user is {passwordAge}");

            // Password min age
            if (passwordAge <= passwordMinAge)
            {
                if (StatusMessage != "Password has been changed.")
                {
                    ModelState.AddModelError(string.Empty,
                        "You recently just changed your password, please try again in 30 seconds.");
                }
                
                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "PasswordUpdateFailed",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                    Reason = "Password was recently changed."
                });

                await _dbContext.SaveChangesAsync();

                PasswordChangeble = false;
                PasswordExpired = false;
            }

            if (passwordAge >= passwordMaxAge)
            {
                
                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "PasswordUpdateFailed",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                    Reason = "Password expired."
                });

                await _dbContext.SaveChangesAsync();
                
                StatusMessage = "Your current password has expired, please set a new password.";
                PasswordExpired = true;
            }

            PasswordChangeble = true;

            // Check for incorrect user password
            var correctPasswordResult =
                _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash,
                    Input.OldPassword);

            // Check for incorrect current password
            if (correctPasswordResult == PasswordVerificationResult.Failed)
            {
                ModelState.AddModelError(string.Empty, "Current password is incorrect.");
                return Page();
            }

            // Check for password history
            // Oldest password would be replaced by new password if update successful
            var result1 =
                _userManager.PasswordHasher.VerifyHashedPassword(user, passwordHistory.Password1,
                    Input.NewPassword);

            var result2 =
                _userManager.PasswordHasher.VerifyHashedPassword(user, passwordHistory.Password2,
                    Input.NewPassword);

            if (result1 == PasswordVerificationResult.Success || result2 == PasswordVerificationResult.Success)
            {
                ModelState.AddModelError(string.Empty,
                    "Your new password cannot be the same as any of your recent passwords. Please choose a new password.");
                
                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "PasswordUpdateFailed",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                    Reason = "New password matches recent passwords."
                });
                
                await _dbContext.SaveChangesAsync();
                
                return Page();
            }


            // Setting the new password for the user
            var changePasswordResult =
                await _userManager.ChangePasswordAsync(user, Input.OldPassword, Input.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                foreach (var error in changePasswordResult.Errors)
                {
                    if (error.Description == "Incorrect password.")
                    {
                        error.Description = "Current password is incorrect.";
                    }

                    ModelState.AddModelError(string.Empty, error.Description);
                }

                _dbContext.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Action = "PasswordUpdateFailed",
                    IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                    Reason = "Incorrect current password."
                });
                
                await _dbContext.SaveChangesAsync();

                return Page();
            }

            // User entry that has password updated
            var updatedUser = _dbContext.Users.Single(entry => entry.Id == user.Id);


            // Update the password entry that is the oldest
            if (passwordHistory.Password1Timestamp < passwordHistory.Password2Timestamp)
            {
                passwordHistory.Password1 = updatedUser.PasswordHash;
                passwordHistory.Password1Timestamp = DateTime.Now;
            }
            else
            {
                passwordHistory.Password2 = updatedUser.PasswordHash;
                passwordHistory.Password2Timestamp = DateTime.Now;
            }

            _dbContext.PasswordHistoryLogs.Update(passwordHistory);

            _dbContext.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Action = "PasswordUpdateSuccess",
                IP = HttpContext.Connection.RemoteIpAddress.ToString(),
                Reason = ""
            });

            await _dbContext.SaveChangesAsync();

            await _signInManager.RefreshSignInAsync(user);
            _logger.LogInformation("User changed their password successfully.");
            StatusMessage = "Password has been changed.";

            return RedirectToPage();
        }
    }
}