using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Core.Entities.Identity
{
    public class User : IdentityUser
    {
        // add any additional properties or navigation properties as needed
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }

    public class Role : IdentityRole
    {
        // add any additional properties or navigation properties as needed
    }

    public class UserClaim : IdentityUserClaim<string>
    {
        // add any additional properties or navigation properties as needed
    }

    public class UserRole : IdentityUserRole<string>
    {
        // add any additional properties or navigation properties as needed
    }

    public class UserLogin : IdentityUserLogin<string>
    {
        // add any additional properties or navigation properties as needed
    }

    public class UserToken : IdentityUserToken<string>
    {
        // add any additional properties or navigation properties as needed
    }
}

