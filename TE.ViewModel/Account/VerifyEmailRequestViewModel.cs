using System.ComponentModel.DataAnnotations;

namespace TE.ViewModel
{
    public class VerifyEmailRequestViewModel
    {
        [Required]
        public string Token { get; set; }
    }
}