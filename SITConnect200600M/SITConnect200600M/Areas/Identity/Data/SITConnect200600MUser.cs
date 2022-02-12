using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace SITConnect200600M.Areas.Identity.Data
{
    // Add profile data for application users by adding properties to the SITConnect200600MUser class
    public class SITConnect200600MUser : IdentityUser
    {
        [Required]
        public string FirstName { get; set; }
        
        [Required]
        public string LastName { get; set; }
        
        // This should be encrypted
        [Required]
        public string CardNumber { get; set; }
        
        [Required]
        [DataType(DataType.Date)]
        public DateTime DateOfBirth { get; set; }
    }
}
