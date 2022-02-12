using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SITConnect200600M.Areas.Identity.Data;

namespace SITConnect200600M.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class EmailNotConfirmed : PageModel
    {
        private readonly UserManager<SITConnect200600MUser> _userManager;

        public EmailNotConfirmed(UserManager<SITConnect200600MUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IActionResult> OnGet()
        {
            var user = await _userManager.GetUserAsync(User);
            
            // Not authenticated
            if (user == null)
            {
                return StatusCode(401);
            }
           
            // If email already confirmed
            if (user.EmailConfirmed)
            {
                return StatusCode(403);
            }

            return Page();
        }
    }
}