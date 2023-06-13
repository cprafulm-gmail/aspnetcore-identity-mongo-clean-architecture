using AutoMapper;

using UserAuthentications.Core.Entities;
using UserAuthentications.Shared.DTOs;

namespace UserAuthentications.Operation.MappingProfiles;

public class PackagesnewMappingProfile : Profile
{
    public PackagesnewMappingProfile()
    {
        CreateMap<Packagesnew, PackagesnewDTO>().ReverseMap();
        CreateMap<Destination, DestinationDTO>().ReverseMap();
        CreateMap<Slot, SlotDTO>().ReverseMap();
        CreateMap<BookBefore, BookBeforeDTO>().ReverseMap();
        CreateMap<AdditionalService, AdditionalServiceDTO>().ReverseMap();
        CreateMap<ItineraryDay, ItineraryDayDTO>().ReverseMap();
        CreateMap<Faq, FaqDTO>().ReverseMap();
        CreateMap<PackageMedia, PackageMediaDTO>().ReverseMap();
    }
}