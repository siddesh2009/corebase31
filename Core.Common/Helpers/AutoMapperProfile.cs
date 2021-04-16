using AutoMapper;
using TE.Entities;
using TE.ViewModel;

namespace TE.Helpers
{
    public class AutoMapperProfile : Profile
    {
        // mappings between model and entity objects
        public AutoMapperProfile()
        {
            CreateMap<Account, AccountResponseViewModel>();

            CreateMap<Account, AuthenticateResponseViewModel>();

            CreateMap<RegisterRequestViewModel, Account>();

            CreateMap<CreateRequestViewModel, Account>();

            CreateMap<UpdateRequestViewModel, Account>()
                .ForAllMembers(x => x.Condition(
                    (src, dest, prop) =>
                    {
                        // ignore null & empty string properties
                        if (prop == null) return false;
                        if (prop.GetType() == typeof(string) && string.IsNullOrEmpty((string)prop)) return false;

                        // ignore null role
                        if (x.DestinationMember.Name == "Role" && src.Role == null) return false;

                        return true;
                    }
                ));
        }
    }
}