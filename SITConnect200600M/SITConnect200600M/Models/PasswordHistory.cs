using System;
using System.ComponentModel.DataAnnotations;

namespace SITConnect200600M.Models
{
    public class PasswordHistory
    {
        [Key] public string UserId { get; set; }

        // Need to set the user's password on registration
        public string Password1 { get; set; } = string.Empty;
        [DataType(DataType.DateTime)] public DateTime Password1Timestamp { get; set; } = DateTime.Now;

        public string Password2 { get; set; } = string.Empty;
        [DataType(DataType.DateTime)] public DateTime Password2Timestamp { get; set; } = DateTime.Now;
    }
}