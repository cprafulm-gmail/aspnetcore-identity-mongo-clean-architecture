using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using UserAuthentications.Infrastructure.Persistence;

namespace UserAuthentications.Core.Entities
{
    public class Packagesnew : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public int PackageID { get; set; }
        public string PackageTitle { get; set; }
        public string[] Category { get; set; }
        public string[] PackageType { get; set; }
        public string[] BestSeasion { get; set; }
        public string CountryName { get; set; }
        public string StateName { get; set; }
        public string CityName { get; set; }
        public int StarRating { get; set; }
        public string MaxAltitude { get; set; }
        public string Difficulty { get; set; }
        public string Distance { get; set; }
        public List<Destination> Destinations { get; set; }
        public string Overview { get; set; }
        public string MainAttraction { get; set; }
        public string PriceGuideLine { get; set; }
        public string TermsConditions { get; set; }
        public string[] Inclusion { get; set; }
        public string[] Exclusion { get; set; }
        public List<ItineraryDay> ItineraryDays { get; set; }
        public List<Faq> Faqs { get; set; }
        public List<PackageMedia> PackageMedia { get; set; }
        public bool IsPublish { get; set; }
        public int PackageCreatedBy { get; set; } = 1;
        public DateTime PackageCreatedDate { get; set; } = DateTime.Now;
        public int PackageUpdatedBy { get; set; } = 1;
        public DateTime PackageUpdatedDate { get; set; } = DateTime.Now;
        public bool PackageIsActive { get; set; } = true;
        public int PackagePriority { get; set; } = 5;

    }
    public class PackageMedia
    {
        public bool IsDefaultImage { get; set; }
        public string FileExtension { get; set; }
        public string FileName { get; set; }
        public string FileURL { get; set; }
    }
    public class Faq
    {
        public string Question { get; set; }
        public string Answer { get; set; }
    }
    public class ItineraryDay
    {
        public string ItineraryTitle { get; set; }
        public string ItineraryDetails { get; set; }
        public string FileURL { get; set; }
    }
    public class Destination
    {
        public string DestinationName { get; set; }
        public List<Slot> Slots { get; set; }
        public decimal AdultPrice { get; set; }
        public decimal ChildPrice { get; set; }
        public int GST { get; set; }
        public int Discount { get; set; }
        public BookBefore BookBefore { get; set; }
        public string PartPaymentType { get; set; }
        public decimal PartPaymentValue { get; set; }
        public List<AdditionalService> AdditionalServices { get; set; }
    }

    public class Slot
    {
        public DateTime Date { get; set; }
        public int Available { get; set; }
        public int Duration { get; set; }
    }

    public class BookBefore
    {
        public int Days { get; set; }
        public bool Refundable { get; set; }
    }

    public class AdditionalService
    {
        public string ServiceName { get; set; }
        public decimal Price { get; set; }
    }
}
