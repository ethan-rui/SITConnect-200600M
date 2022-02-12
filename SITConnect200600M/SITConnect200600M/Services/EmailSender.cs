using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace SITConnect200600M.Services
{
    public class EmailSender: IEmailSender 
    {
        private readonly IConfiguration _configuration;
        
        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
            _sendGridEmail = _configuration["SendGridEmail"];
            _sendGridKey = _configuration["SendGridKey"];
            _sendGridName = _configuration["SendGridName"];
        }

        // Values for SendGrid, set it in appsettings.json
        private readonly string _sendGridKey;
        private readonly string _sendGridName;
        private readonly string _sendGridEmail;


        public Task SendEmailAsync(string email, string subject, string message)
        {
            return Execute(_sendGridKey, subject, message, email);
        }

        public Task Execute(string apiKey, string subject, string message, string email)
        {
            var client = new SendGridClient(apiKey);
            var msg = new SendGridMessage()
            {
                From = new EmailAddress(_sendGridEmail, _sendGridName),
                Subject = subject,
                PlainTextContent = message,
                HtmlContent = message
            };
            msg.AddTo(new EmailAddress(email));

            // Disable click tracking.
            // See https://sendgrid.com/docs/User_Guide/Settings/tracking.html
            msg.SetClickTracking(false, false);

            return client.SendEmailAsync(msg);
        }
    }
}