using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using UserAuthentications.Infrastructure.Persistence;

namespace UserAuthentications.Core.Entities
{
    public class Package : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public int PackageID { get; set; }
        public string PackageTitle { get; set; }
        public DateTime[] PackageSlots { get; set; }
        public string PackageType { get; set; }
        public string Duration { get; set; }
        public int CategoryID { get; set; }
        public string BestSeasion { get; set; }
        public string[] Destinations { get; set; }
        public int MaxTravellers { get; set; }
        public int CountryID { get; set; }
        public int StateID { get; set; }
        public int CityID { get; set; }
        public string StarRationg { get; set; }
        public bool IsPublish { get; set; }
        public int AdultPrice { get; set; }
        public int ChildPrice { get; set; }
        public int DiscountPrice { get; set; }
        public int Percentage { get; set; }
        public bool IsInclusive { get; set; }
        public int CGSTPrice { get; set; }
        public int SGSTPrice { get; set; }
        public int PartPayment { get; set; }
        public DateTime BookBefore { get; set; }
        public int TotalAmount { get; set; }
        public int AmountWithoutGST { get; set; }
        public string Overview { get; set; }
        public string PriceGuideLine { get; set; }
        public string TermsConditions { get; set; }
        public string InclusionExclusion { get; set; }
        public ItineraryDays[] ItineraryDays { get; set; }
        public Faqs[] Faqs { get; set; }
        public MediaContents[] galleryImages { get; set; }
        public int PackageCreatedBy { get; set; } = 1;
        public DateTime PackageCreatedDate { get; set; } = DateTime.Now;
        public int PackageUpdatedBy { get; set; } = 1;
        public DateTime PackageUpdatedDate { get; set; } = DateTime.Now;
        public bool PackageIsActive { get; set; } = true;

    }
    public class MediaContents : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public bool IsDefaultImage { get; set; }
        public string FileExtension { get; set; }
        public string FileContentType { get; set; }
        public string FileData { get; set; }
        public string FileName { get; set; }
        public string FileURL { get; set; }
        public bool IsActive { get; set; } = false;
    }

    public class ItineraryDays : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public string itineraryTitle { get; set; }
        public string itineraryDetails { get; set; }
        public MediaContents MediaContents { get; set; } = new MediaContents();
    }
    public class Faqs : IIdentifiable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public string Id { get; set; }
        public string Question { get; set; }
        public string Answer { get; set; }
    }

}
