using System;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Data;

[assembly: HostingStartup(typeof(SITConnect200600M.Areas.Identity.IdentityHostingStartup))]

namespace SITConnect200600M.Areas.Identity
{
    public class IdentityHostingStartup : IHostingStartup
    {
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureServices((context, services) =>
            {
                services.AddDbContext<SITConnect200600MContext>(options =>
                    options.UseSqlServer(
                        context.Configuration.GetConnectionString("SITConnect200600MContextConnection")));

                // Set up email verification here
                services.AddDefaultIdentity<SITConnect200600MUser>(options =>
                    {
                        options.SignIn.RequireConfirmedAccount = true;

                        // Registration form password requirements.
                        options.Password.RequiredLength = 12;
                        options.Password.RequireDigit = true;
                        options.Password.RequireLowercase = true;
                        options.Password.RequireUppercase = true;
                        options.Password.RequiredUniqueChars = 1;
                        options.Password.RequireNonAlphanumeric = true;

                        // Account lockout requirements.
                        options.Lockout.MaxFailedAccessAttempts = 3;
                        options.Lockout.DefaultLockoutTimeSpan =
                            TimeSpan.FromSeconds(context.Configuration.GetValue<int>("AccountLockoutDurationSeconds"));
                        options.Lockout.AllowedForNewUsers = true;
                    })
                    .AddEntityFrameworkStores<SITConnect200600MContext>();
                services
                    .AddScoped<IUserClaimsPrincipalFactory<SITConnect200600MUser>,
                        AdditionalUserClaimsPrincipalFactory>();


                services.ConfigureApplicationCookie(options =>
                {
                    options.AccessDeniedPath = "/StatusCode?code=403";
                    options.Cookie.Name = ".AspNetCore.Identity.Application";
                    options.Cookie.HttpOnly = true;
                    options.ExpireTimeSpan =
                        TimeSpan.FromSeconds(context.Configuration.GetValue<int>("SessionTimeoutDurationSeconds"));
                    
                    options.LoginPath = "/Identity/Account/Login";
                    options.ReturnUrlParameter = CookieAuthenticationDefaults.ReturnUrlParameter;
                    options.SlidingExpiration = true;
                });
                
            });
        }
    }
}