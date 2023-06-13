using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Shared.DTOs
{
    public class PackageDTO
    {
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
        public ItineraryDaysDTO[] ItineraryDays { get; set; }
        public FaqsDTO[] Faqs { get; set; }
        public MediaContentsDTO[] GalleryImages { get; set; }
        public int PackageCreatedBy { get; set; }
        public DateTime? PackageCreatedDate { get; set; }
        public int PackageUpdatedBy { get; set; }
        public DateTime? PackageUpdatedDate { get; set; }
        public bool? PackageIsActive { get; set; }
        public int PackagePriority { get; set; }
    }

    public class MediaContentsDTO
    {
        public string? Id { get; set; }
        public bool IsDefaultImage { get; set; }
        public string FileExtension { get; set; }
        public string FileContentType { get; set; }
        public string FileData { get; set; }
        public string FileName { get; set; }
        public string FileURL { get; set; }
        public bool? IsActive { get; set; }
    }

    public class ItineraryDaysDTO
    {
        public string? Id { get; set; }
        public string ItineraryTitle { get; set; }
        public string ItineraryDetails { get; set; }
        public MediaContentsDTO MediaContents { get; set; }
    }
    public class FaqsDTO
    {
        public string? Id { get; set; }
        public string Question { get; set; }
        public string Answer { get; set; }
    }

}
