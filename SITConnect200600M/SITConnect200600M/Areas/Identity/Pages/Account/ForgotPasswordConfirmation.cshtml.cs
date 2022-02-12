using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SITConnect200600M.Areas.Identity.Data;

namespace SITConnect200600M.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ForgotPasswordConfirmation : PageModel
    {
        private readonly UserManager<SITConnect200600MUser> _userManager;

        public ForgotPasswordConfirmation(UserManager<SITConnect200600MUser> userManager)
        {
            _userManager = userManager;
        }

        public void OnGet()
        {
        }
    }
}