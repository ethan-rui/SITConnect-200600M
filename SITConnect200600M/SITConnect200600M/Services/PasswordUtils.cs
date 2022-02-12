using System;
using System.Linq;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;

namespace SITConnect200600M.Services
{
    public class PasswordUtils
    {
        private readonly UserManager<SITConnect200600MUser> _userManager;
        private readonly SignInManager<SITConnect200600MUser> _signInManager;
        private readonly ILogger<PasswordUtils> _logger;
        private readonly SITConnect200600MContext _dbContext;
        private readonly IConfiguration _configuration;

        public PasswordUtils(
            UserManager<SITConnect200600MUser> userManager,
            ILogger<PasswordUtils> logger,
            SITConnect200600MContext dbContext,
            SignInManager<SITConnect200600MUser> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _logger = logger;
            _dbContext = dbContext;
            _signInManager = signInManager;
            _configuration = configuration;
            
            // Password age
            passwordMinAge = _configuration.GetValue<int>("PasswordMinAgeSeconds");
            passwordMaxAge = _configuration.GetValue<int>("PasswordMaxAgeSeconds");

        }
        
        public int passwordMinAge { get; }
        public int passwordMaxAge { get; }

        public DateTime GetMostRecentPasswordChange(string userId)
        {
            // Get password logs for the current user
            var passwordHistory = _dbContext.PasswordHistoryLogs.Single(entry => entry.UserId == userId);
            
            // Current password age
            return passwordHistory.Password1Timestamp < passwordHistory.Password2Timestamp ? passwordHistory.Password2Timestamp : passwordHistory.Password1Timestamp;
        }

        public double TimeDifferenceInSeconds(DateTime value)
        {
            return (DateTime.Now - value).TotalSeconds;
        }

        public bool IsPasswordExpired(string userId)
        {
            var recentPasswordChange = GetMostRecentPasswordChange(userId);
            var passwordAge = TimeDifferenceInSeconds(recentPasswordChange);
            return passwordAge >= passwordMaxAge;
        }

        public bool IsPasswordCooldown(string userId)
        {
            var recentPasswordChange = GetMostRecentPasswordChange(userId);
            var passwordAge = TimeDifferenceInSeconds(recentPasswordChange);
            return passwordAge <= passwordMinAge;
        }

    }
}