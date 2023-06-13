using AutoMapper;

using UserAuthentications.Core.Entities;
using UserAuthentications.Shared.DTOs;

namespace UserAuthentications.Operation.MappingProfiles;

public class BookingInfoMappingProfile : Profile
{
    public BookingInfoMappingProfile()
    {
        CreateMap<BookingInfo, BookingInfoDTO>().ReverseMap();
        CreateMap<BookingPaxInfo, BookingPaxInfoDTO>().ReverseMap();
        CreateMap<PaymentInfo, PaymentInfoDTO>().ReverseMap();
    }
}