using System.ComponentModel.DataAnnotations;
using UserAuthentications.Infrastructure.Persistence;

namespace UserAuthentications.Core.Entities
{
    public class Country: IIdentifiable
    {
        
        public string? Id { get; set; }

        public int CountryId { get; set; }

        public string CountryName { get; set; }

        public string? CountryCode { get; set; }

        public string CountryDailCode { get; set; }

        public State State { get; set; } = new State();

        public int CountryCreatedBy { get; set; }

        public DateTime? CountryCreatedDate { get; set; } = DateTime.Now;

        public int CountryUpdatedBy { get; set; }

        public DateTime? CountryUpdatedDate { get; set; } = DateTime.Now;

        public bool? CountryIsActive { get; set; } = true;

    }
    public class State: IIdentifiable
    {
        public string? Id { get; set; }

        public int StateId { get; set; }

        public string StateName { get; set; }

        public City City { get; set; } = new City();

        public int StateCreatedBy { get; set; }

        public DateTime? StateCreatedDate { get; set; } = DateTime.Now;

        public int StateUpdatedBy { get; set; }

        public DateTime? StateUpdatedDate { get; set; } = DateTime.Now;

        public bool? StateIsActive { get; set; } = true;

    }

    public class City: IIdentifiable
    {
        public string? Id { get; set; }

        public int CityId { get; set; }

        public string CityName { get; set; }

        public int CityCreatedBy { get; set; }

        public DateTime? CityCreatedDate { get; set; } = DateTime.Now;

        public int CityUpdatedBy { get; set; }

        public DateTime? CityUpdatedDate { get; set; } = DateTime.Now;

        public bool? CityIsActive { get; set; } = true;
    }
}
