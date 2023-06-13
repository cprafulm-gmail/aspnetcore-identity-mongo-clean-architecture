using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Shared.DTOs
{

    public class BookingInfoDTO
    {
        public string Id { get; set; }
        public string BookingNumber { get; set; }
        public string PackageId { get; set; }
        public string BookingStatus { get; set; }
        public string PaymentId { get; set; }
        public string UserId { get; set; }
        public string SpecialNotes { get; set; }
        public DateTime BookingDate { get; set; }
        public string PackageTripSchedule { get; set; }
        public string BookingPaymentStatus { get; set; }
        public string DepartureLocation { get; set; }
        public int AdultCount { get; set; }
        public int ChildCount { get; set; }
        public decimal PackageAmount { get; set; }
        public BookingPaxInfoDTO[] BookingPaxInfo { get; set; }
        public PaymentInfoDTO[] PaymentInfo { get; set; }
    }
    public class BookingPaxInfoDTO
    {
        public string BookingPaxInfoId { get; set; }
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
        public string IdproofId { get; set; }
        public string IdproofValue { get; set; }
    }

    public class PaymentInfoDTO
    {
        public string PaymentId { get; set; }
        public string TransactionToken { get; set; }
        public string GatewayRef { get; set; }
        public DateTime PaymentDate { get; set; }
        public decimal PaymentAmount { get; set; }
        public string UserId { get; set; }
        public string PackageId { get; set; }
        public string PGPaymentStatus { get; set; }
    }
}
