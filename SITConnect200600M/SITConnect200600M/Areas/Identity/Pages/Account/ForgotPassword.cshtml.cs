using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;
using SITConnect200600M.Services;

namespace SITConnect200600M.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<SITConnect200600MUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly reCAPTCHAv3 _reCaptchaService;
        private readonly SITConnect200600MContext _dbContext;
        private readonly IConfiguration _configuration;

        public ForgotPasswordModel(
            UserManager<SITConnect200600MUser> userManager,
            IEmailSender emailSender,
            SITConnect200600MContext dbContext,
            reCAPTCHAv3 reCaptchaService, IConfiguration configuration)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _dbContext = dbContext;
            _reCaptchaService = reCaptchaService;
            _configuration = configuration;

            reCaptchaKey = _configuration["reCaptchaKeyClientSide"];
        }

        [BindProperty] public InputModel Input { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "The email field is required")]
            [EmailAddress(ErrorMessage = "This is not a valid email address")]
            public string Email { get; set; }
            
            [Required] public string Token { get; set; }
        }
        
        public string reCaptchaKey { get; set; }

        public async Task<IActionResult> OnPostAsync()
        {
            var reCaptchaResult = _reCaptchaService.TokenVerify(Input.Token);
            if (!reCaptchaResult.Result.IsSuccess || reCaptchaResult.Result.Score <= 0.8 )
            {
                ModelState.AddModelError(string.Empty, "Invalid captcha response, please try again.");
                return Page();
            }
            
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(Input.Email);
                if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return RedirectToPage("./ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please 
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Page(
                    "/Account/ResetPassword",
                    pageHandler: null,
                    values: new {area = "Identity", code},
                    protocol: Request.Scheme);

                await _emailSender.SendEmailAsync(
                    Input.Email,
                    "Reset Password",
                    $"Please reset your password by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                return RedirectToPage("./ForgotPasswordConfirmation");
            }

            return Page();
        }
    }
}