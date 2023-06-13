using AutoMapper;

using UserAuthentications.Core.Entities;
using UserAuthentications.Shared.DTOs;

namespace UserAuthentications.Operation.MappingProfiles;

public class PackageMappingProfile : Profile
{
    public PackageMappingProfile()
    {
        CreateMap<Package, PackageDTO>().ReverseMap();
        CreateMap<ItineraryDays, ItineraryDaysDTO>().ReverseMap();
        CreateMap<Faqs, FaqsDTO>().ReverseMap();
        CreateMap<MediaContents, MediaContentsDTO>().ReverseMap();
    }
}