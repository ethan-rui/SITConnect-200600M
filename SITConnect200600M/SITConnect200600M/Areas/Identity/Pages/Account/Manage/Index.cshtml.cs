using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;
using SITConnect200600M.Services;

namespace SITConnect200600M.Areas.Identity.Pages.Account.Manage
{
    [AllowAnonymous]
    public partial class IndexModel : PageModel
    {
        private readonly UserManager<SITConnect200600MUser> _userManager;
        private readonly SignInManager<SITConnect200600MUser> _signInManager;
        private readonly SITConnect200600MContext _dbContext;
        private readonly IConfiguration _configuration;
        private readonly PasswordUtils _pwdUtils;

        public IndexModel(
            UserManager<SITConnect200600MUser> userManager,
            SignInManager<SITConnect200600MUser> signInManager, 
            SITConnect200600MContext dbContext, 
            IConfiguration configuration,
            PasswordUtils pwdUtils)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _dbContext = dbContext;
            _configuration = configuration;
            _pwdUtils = pwdUtils;
        }

        [BindProperty]
        public SITConnect200600MUser CurrentUser { get; set; }

        private async Task LoadAsync(SITConnect200600MUser user)
        {
            var userId = _userManager.GetUserId(User);
            CurrentUser = await _dbContext.Users.SingleAsync(entry => entry.Id == userId);
            CurrentUser.CardNumber = CreditCardCryptography.DecryptStringAes(CurrentUser.CardNumber, _configuration["AESKey"]);
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            
            // If user is not authenticated
            if (user == null)
            {
                return StatusCode(401);
            }
            
            if(_pwdUtils.IsPasswordExpired(_userManager.GetUserId(User)))
            {
                return LocalRedirect("/Identity/Account/Manage/ChangePassword");
            }

            await LoadAsync(user);
            return Page();
        }
    }
}
