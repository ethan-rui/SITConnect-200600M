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
using SITConnect200600M.Data;
using SITConnect200600M.Models;

namespace SITConnect200600M.Areas.Identity.Pages.Account
{
    [Authorize]
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<SITConnect200600MUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        private readonly SITConnect200600MContext _dbContext;
        private readonly UserManager<SITConnect200600MUser> _userManager;

        public LogoutModel(
            SignInManager<SITConnect200600MUser> signInManager,
            ILogger<LogoutModel> logger,
            SITConnect200600MContext dbContext, UserManager<SITConnect200600MUser> userManager)
        {
            _signInManager = signInManager;
            _logger = logger;
            _dbContext = dbContext;
            _userManager = userManager;
        }

        public IActionResult OnGet()
        {
            return LocalRedirect("/Identity/Account/Login");
        }

        public async Task<IActionResult> OnPost(string returnUrl = null)
        {
            if (_signInManager.IsSignedIn(User))
            {
                await _signInManager.SignOutAsync();
                _logger.LogInformation("User logged out.");
            }
            
            // Logging successful logout into db
            _dbContext.AuditLogs.Add(new AuditLog
            {
                UserId = _userManager.GetUserId(User),
                Action = "LogoutSucess",
                IP = HttpContext.Connection.RemoteIpAddress.ToString(),
            });
            await _dbContext.SaveChangesAsync();
                
            return LocalRedirect("/Identity/Account/Login");
        }
    }
}
