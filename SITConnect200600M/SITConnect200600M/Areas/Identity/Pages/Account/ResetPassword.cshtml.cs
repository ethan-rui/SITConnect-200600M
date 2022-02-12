using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;
using SITConnect200600M.Models;
using SITConnect200600M.Services;

namespace SITConnect200600M.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<SITConnect200600MUser> _userManager;
        private readonly reCAPTCHAv3 _reCaptchaService;
        private readonly SITConnect200600MContext _dbContext;
        private readonly IConfiguration _configuration;

        public ResetPasswordModel(
            UserManager<SITConnect200600MUser> userManager,
            IConfiguration configuration,
            SITConnect200600MContext dbContext,
            reCAPTCHAv3 reCaptchaService
        )
        {
            _userManager = userManager;
            _configuration = configuration;
            _dbContext = dbContext;
            _reCaptchaService = reCaptchaService;

            reCaptchaKey = _configuration["reCaptchaKeyClientSide"];
        }

        public string reCaptchaKey { get; set; }

        [BindProperty] public InputModel Input { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "Email field is required.")]
            [EmailAddress(ErrorMessage = "This is not a valid email address.")]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required(ErrorMessage = "Password field is required")]
            [StringLength(100, ErrorMessage = "Password must be at least {2} characters long.", MinimumLength = 12)]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }

            public string Code { get; set; }

            [Required] public string Token { get; set; }
        }

        public IActionResult OnGet(string code = null)
        {
            if (code == null)
            {
                return StatusCode(403);
            }
            else
            {
                Input = new InputModel
                {
                    Code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code))
                };
                return Page();
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
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

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToPage("./ResetPasswordConfirmation");
            }

            var result = await _userManager.ResetPasswordAsync(user, Input.Code, Input.Password);
            if (result.Succeeded)
            {
                // Updating the password history
                var passwordHistory = _dbContext.PasswordHistoryLogs.Single(entry => entry.UserId == user.Id);
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

                return RedirectToPage("./ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
    }
}