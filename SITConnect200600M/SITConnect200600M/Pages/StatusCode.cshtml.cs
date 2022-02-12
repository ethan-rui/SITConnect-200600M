using System;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SITConnect200600M.Pages
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class StatusCode : PageModel
    {
        public int OriginalStatusCode { get; set; }
        public string ErrorMessage { get; set; }
        public string ErrorHeading { get; set; }

        public string? OriginalPathAndQuery { get; set; }

        public IActionResult OnGet(int code)
        {
            OriginalStatusCode = code;
            Console.WriteLine(OriginalStatusCode);

            var statusCodeReExecuteFeature =
                HttpContext.Features.Get<IStatusCodeReExecuteFeature>();

            if (statusCodeReExecuteFeature != null)
            {
                OriginalPathAndQuery = string.Join(
                    statusCodeReExecuteFeature.OriginalPathBase,
                    statusCodeReExecuteFeature.OriginalPath,
                    statusCodeReExecuteFeature.OriginalQueryString);
            }

            switch (OriginalStatusCode)
            {
                case 400:
                    ErrorMessage = "Sorry, the request was malformed or illegal.";
                    ErrorHeading = "Bad request.";
                    break;
                case 401:
                    ErrorMessage = "Sorry, you need to be logged in to view this content.";
                    ErrorHeading = "Unauthorized.";
                    break;
                case 404:
                    ErrorMessage = $"Sorry, the requested URL {OriginalPathAndQuery} was not found.";
                    ErrorHeading = "Page not found.";
                    break;
                case 403:
                    ErrorMessage = "Sorry, you do not have access to this document.";
                    ErrorHeading = "Forbidden.";
                    break;
                case 500:
                    ErrorMessage = "Sorry, the server encountered an error and was unable to complete your request.";
                    ErrorHeading = "Internal server error.";
                    break;
                default:
                    return LocalRedirect("/");
            }
            
            return Page();
        }
    }
}