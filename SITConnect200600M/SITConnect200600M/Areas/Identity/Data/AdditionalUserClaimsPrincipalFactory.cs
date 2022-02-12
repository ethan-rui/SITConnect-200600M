using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace SITConnect200600M.Areas.Identity.Data
{
    public class AdditionalUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<SITConnect200600MUser>
    {
        public AdditionalUserClaimsPrincipalFactory
        (UserManager<SITConnect200600MUser> userManager,
            IOptions<IdentityOptions> optionsAccessor,
            IConfiguration configuration) : base(userManager, optionsAccessor)
        {
            _configuration = configuration;
        }

        private readonly IConfiguration _configuration;

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(SITConnect200600MUser user)
        {
            var identity = await base.GenerateClaimsAsync(user);

            identity.AddClaim(new Claim("FullName", $"{user.FirstName.ToUpper()} {user.LastName.ToUpper()}"));
            identity.AddClaim(new Claim("CardNumber", CreditCardCryptography.DecryptStringAes(user.CardNumber, _configuration["AESKey"])));

            return identity;
        }
    }
}