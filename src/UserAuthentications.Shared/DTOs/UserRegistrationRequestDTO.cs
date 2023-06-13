using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dejavu.Crs.Shared.DTOs
{
    public class UserRegistrationRequestDTO
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FacebookAccessToken { get; set; }
        public string GoogleAccessToken { get; set; }
    }
}
