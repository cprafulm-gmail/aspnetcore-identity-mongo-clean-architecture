using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Shared.DTOs
{
    public class UserLoginRequestDTO
    {
        public string Password { get; set; }
        public string FacebookAccessToken { get; set; }
        public string GoogleAccessToken { get; set; }
    }
}
