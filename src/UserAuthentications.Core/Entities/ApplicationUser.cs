using AspNetCore.Identity.MongoDbCore.Models;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Core.Entities
{
    public class ApplicationUser : MongoIdentityUser<Guid>
    {
        public Guid userId;

        //[BsonId]
        //[BsonRepresentation(BsonType.String)]
        //public override Guid Id { get; set; }

        //[PersonalData]
        //[BsonElement("firstName")]
        //public string FirstName { get; set; }

        //[PersonalData]
        //[BsonElement("lastName")]
        //public string LastName { get; set; }

        //[PersonalData]
        //[BsonElement("email")]
        //public override string Email { get; set; }

        //[PersonalData]
        //[BsonElement("mobile")]
        //public string Mobile { get; set; }

        //[PersonalData]
        //[BsonElement("isEmailVerified")]
        //public bool IsEmailVerified { get; set; }

        //[PersonalData]
        //[BsonElement("isMobileVerified")]
        //public bool IsMobileVerified { get; set; }

        //[PersonalData]
        //[BsonElement("passwordHash")]
        //public override string PasswordHash { get; set; }

        //[PersonalData]
        //[BsonElement("refreshToken")]
        //public string RefreshToken { get; set; }

        //[PersonalData]
        //[BsonElement("refreshTokenExpiryTime")]
        //public DateTime RefreshTokenExpiryTime { get; set; }

        //[PersonalData]
        //[BsonElement("isActive")]
        //public bool IsActive { get; set; }

        //[PersonalData]
        //[BsonElement("createdDate")]
        //public DateTime CreatedDate { get; set; }

        //[PersonalData]
        //[BsonElement("modifiedDate")]
        //public DateTime ModifiedDate { get; set; }

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Gender { get; set; }
        public DateTime Birthdate { get; set; }

        public virtual ICollection<CoTraveller> CoTravellers { get; set; }
        public DateTime ModifiedDate { get; set; }
        public bool IsActive { get; set; }

        public ApplicationUser()
        {
            // set default values for the new fields
            FirstName = "";
            LastName = "";
            Birthdate = DateTime.MinValue;
            CoTravellers = new List<CoTraveller>();
            ModifiedDate = DateTime.Now;
            IsActive = true;
        }
        //public ApplicationUser() : base()
        //{
        //}

        //public ApplicationUser(string userName, string email, string firstName, string lastName, string phoneNumber) : base(userName, email)
        //{
        //}
    }
    public class CoTraveller
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string Gender { get; set; }
        public DateTime Birthdate { get; set; }
        // Add other properties as needed
    }

}
