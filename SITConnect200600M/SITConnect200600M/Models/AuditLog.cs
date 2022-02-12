using System;
using System.ComponentModel.DataAnnotations;

namespace SITConnect200600M.Models
{
    public class AuditLog
    {
        [Key] public string Id { get; set; } = Guid.NewGuid().ToString();

        public string Action { get; set; }

        public string Reason { get; set; } = String.Empty;

        [DataType(DataType.DateTime)] public DateTime TimeStamp { get; set; } = DateTime.Now;

        public string UserId { get; set; }

        public string IP { get; set; }
    }
}