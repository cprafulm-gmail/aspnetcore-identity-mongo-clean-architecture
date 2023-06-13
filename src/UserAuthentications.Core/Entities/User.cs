using AspNetCore.Identity.MongoDbCore.Models;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;
using System.ComponentModel.DataAnnotations.Schema;

namespace UserAuthentications.Core.Entities
{
    public class User : MongoIdentityUser<Guid>
    {
        public User() : base()
        {
        }

        public User(string userName, string email) : base(userName, email)
        {
        }
    }
    public class UserLoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
