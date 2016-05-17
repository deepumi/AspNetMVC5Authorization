using System.ComponentModel.DataAnnotations;

namespace AspNetMVC5Authorization.ViewModels
{
    public class SignInViewModel
    {
        [Required(ErrorMessage="Email is required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public string ErrorMessage { get; set; }
    }
}