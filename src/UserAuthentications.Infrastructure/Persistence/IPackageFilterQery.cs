namespace UserAuthentications.Infrastructure.Persistence;

public interface IPackageFilterQery
{
    string? PackageTitle { get; }
    string[]? Category { get; }
    string[]? PackageType { get; }
    string[]? BestSeasion { get; }
    string? CountryName { get; }
    string? StateName { get; }
    string? CityName { get; }
    string? DestinationName { get; }
    int? minDuration { get; }
    int? maxDuration { get; }
    DateTime? startSlots { get; }
    DateTime? endSlots { get; }
    int? minAdultPrice { get; }
    int? maxAdultPrice { get; }
}