using System.ComponentModel.DataAnnotations;

namespace TE.ViewModel
{
    public class ValidateResetTokenRequestViewModel
    {
        [Required]
        public string Token { get; set; }
    }
}