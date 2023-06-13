using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Shared.DTOs
{
    public class PackagesnewDTO
    {
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
        public List<DestinationDTO> Destinations { get; set; }
        public string Overview { get; set; }
        public string MainAttraction { get; set; }
        public string PriceGuideLine { get; set; }
        public string TermsConditions { get; set; }
        public string[] Inclusion { get; set; }
        public string[] Exclusion { get; set; }
        public List<ItineraryDayDTO> ItineraryDays { get; set; }
        public List<FaqDTO> Faqs { get; set; }
        public List<PackageMediaDTO> PackageMedia { get; set; }
        public bool IsPublish { get; set; }
        public int PackageCreatedBy { get; set; } = 1;
        public DateTime PackageCreatedDate { get; set; } = DateTime.Now;
        public int PackageUpdatedBy { get; set; } = 1;
        public DateTime PackageUpdatedDate { get; set; } = DateTime.Now;
        public bool PackageIsActive { get; set; } = true;

    }
    public class PackageMediaDTO
    {
        public bool IsDefaultImage { get; set; }
        public string FileExtension { get; set; }
        public string FileName { get; set; }
        public string FileURL { get; set; }
    }
    public class FaqDTO
    {
        public string Question { get; set; }
        public string Answer { get; set; }
    }
    public class ItineraryDayDTO
    {
        public string ItineraryTitle { get; set; }
        public string ItineraryDetails { get; set; }
        public string FileURL { get; set; }
    }
    public class DestinationDTO
    {
        public string DestinationName { get; set; }
        public List<SlotDTO> Slots { get; set; }
        public decimal AdultPrice { get; set; }
        public decimal ChildPrice { get; set; }
        public int GST { get; set; }
        public int Discount { get; set; }
        public BookBeforeDTO BookBefore { get; set; }
        public string PartPaymentType { get; set; }
        public decimal PartPaymentValue { get; set; }
        public List<AdditionalServiceDTO> AdditionalServices { get; set; }
    }

    public class SlotDTO
    {
        public DateTime Date { get; set; }
        public int Available { get; set; }
        public int Duration { get; set; }
    }

    public class BookBeforeDTO
    {
        public int Days { get; set; }
        public bool Refundable { get; set; }
    }

    public class AdditionalServiceDTO
    {
        public string ServiceName { get; set; }
        public decimal Price { get; set; }
    }
}
