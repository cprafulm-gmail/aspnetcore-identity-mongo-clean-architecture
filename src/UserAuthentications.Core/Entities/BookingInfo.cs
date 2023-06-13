using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using UserAuthentications.Infrastructure.Persistence;

namespace UserAuthentications.Core.Entities
{
    public class BookingInfo : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }

        [Required]
        [StringLength(20)]
        public string BookingNumber { get; set; }

        public string PackageId { get; set; }

        [Required]
        [StringLength(20)]
        public string BookingStatus { get; set; }

        public string PaymentId { get; set; }

        public string UserId { get; set; }

        [StringLength(500)]
        public string SpecialNotes { get; set; }

        public DateTime BookingDate { get; set; }

        public string PackageTripSchedule { get; set; }

        [Required]
        [StringLength(20)]
        public string BookingPaymentStatus { get; set; }

        public string DepartureLocation { get; set; }

        public int AdultCount { get; set; }

        public int ChildCount { get; set; }

        public decimal PackageAmount { get; set; }


        public BookingPaxInfo[] BookingPaxInfo { get; set; }
        public PaymentInfo[] PaymentInfo { get; set; }
    }

    public class BookingPaxInfo : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public string PackageId { get; set; }
        public string BookingId { get; set; }
        public string Name { get; set; }
        public string Gender { get; set; }
        public DateTime BirthDate { get; set; }
        public string Phone { get; set; }
        public string Email { get; set; }
        public string Address { get; set; }
        public string City { get; set; }
        public string State { get; set; }
        public string Country { get; set; }
        public string IdProofId { get; set; }
        public string IdProofValue { get; set; }
    }

    public class PaymentInfo : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public string TransactionToken { get; set; }
        public string GatewayRef { get; set; }
        public DateTime PaymentDate { get; set; }
        public decimal PaymentAmount { get; set; }
        public string UserId { get; set; }
        public string PackageId { get; set; }
        public string PGPaymentStatus { get; set; }
    }
}
