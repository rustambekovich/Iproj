using AutoMapper;
using IdentityServer4.EntityFramework.Entities;
using IdentityServer4.Models;

namespace Iproj.Services;

public class IdentityServerMappingProfile : Profile
{
    public IdentityServerMappingProfile()
    {
        CreateMap<IdentityServer4.Models.Client, IdentityServer4.EntityFramework.Entities.Client>()
            .ReverseMap()
            .ForMember(dest => dest.ClientSecrets, opt => opt.MapFrom(src => src.ClientSecrets.Select(s => new ClientSecret
            {
                Description = s.Description,
                Expiration = s.Expiration,
                Value = s.Value,
                Type = s.Type
            })))
            .ReverseMap()
            .ForMember(dest => dest.ClientSecrets, opt => opt.MapFrom(src => src.ClientSecrets.Select(s => new IdentityServer4.Models.Secret
            {
                Description = s.Description,
                Expiration = s.Expiration,
                Value = s.Value,
                Type = s.Type
            })));
    }
}
