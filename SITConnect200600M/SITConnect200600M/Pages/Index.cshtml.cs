using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Services;

namespace SITConnect200600M.Pages
{
    [Authorize]
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly PasswordUtils _pwdUtils;
        private readonly UserManager<SITConnect200600MUser> _userManager;

        public IndexModel(
            ILogger<IndexModel> logger,
            PasswordUtils pwdUtils,
            UserManager<SITConnect200600MUser> userManager)
        {
            _logger = logger;
            _pwdUtils = pwdUtils;
            _userManager = userManager;
        }

        public IActionResult OnGet()
        {
            if(_pwdUtils.IsPasswordExpired(_userManager.GetUserId(User)))
            {
                return LocalRedirect("/Identity/Account/Manage/ChangePassword");
            }

            return Page();
        }
    }
}