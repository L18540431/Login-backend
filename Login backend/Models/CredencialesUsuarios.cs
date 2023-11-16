using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Login_backend.Models
{
    public class CredencialesUsuarios
    {
        [Required]
        [EmailAddress]
        public String Email { get; set; }
        
        [Required]
        public string Password { get; set; } 
    }
}
