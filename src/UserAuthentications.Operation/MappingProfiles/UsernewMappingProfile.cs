using AutoMapper;

using UserAuthentications.Core.Entities;
using UserAuthentications.Shared.DTOs;

namespace UserAuthentications.Operation.MappingProfiles;

public class UsernewMappingProfile : Profile
{
    //public UserMappingProfile()
    //{
    //    CreateMap<User, UserDTO>().ReverseMap();
    //}
    public UsernewMappingProfile()
    {
        CreateMap<UsernewDTO, Usernew>()
            .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email)); // assuming email will be the username
    }
}