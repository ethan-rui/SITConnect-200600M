using System;
using System.ComponentModel.DataAnnotations;

namespace SITConnect200600M.Areas.Identity.Data
{
    public class DOBRangeAttribute: ValidationAttribute
    {
        public override bool IsValid(object value)
        {
            var minDate = new DateTime(1900, 1, 1);
            var inputDate = Convert.ToDateTime(value);
            DateTime maxDate = DateTime.Now;
            return inputDate >= minDate && inputDate <= maxDate;
        }
    }
}