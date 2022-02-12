using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SITConnect200600M.Areas.Identity.Data;
using SITConnect200600M.Models;

namespace SITConnect200600M.Data
{
    public class SITConnect200600MContext : IdentityDbContext<SITConnect200600MUser>
    {
        public SITConnect200600MContext(
            DbContextOptions<SITConnect200600MContext> options
        )
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }

        public virtual DbSet<SITConnect200600MUser> Users { get; set; }
        public virtual DbSet<AuditLog> AuditLogs { get; set; }
        public virtual DbSet<PasswordHistory> PasswordHistoryLogs { get; set; }
    }
}