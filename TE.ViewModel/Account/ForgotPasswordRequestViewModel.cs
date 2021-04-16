using System.ComponentModel.DataAnnotations;

namespace TE.ViewModel
{
    public class ForgotPasswordRequestViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}