using System.ComponentModel.DataAnnotations;

namespace TE.ViewModel
{
    public class AuthenticateRequestViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}