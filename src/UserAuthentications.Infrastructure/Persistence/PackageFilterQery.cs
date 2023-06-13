namespace UserAuthentications.Infrastructure.Persistence;

public class PackageFilterQery : IPackageFilterQery
{
    public string? PackageTitle { get; set; } = "";
    public string[]? Category { get; set; } = new string[0];
    public string[]? PackageType { get; set; } = new string[0];
    public string[]? BestSeasion { get; set; } = new string[0];
    public string? CountryName { get; set; } = "";
    public string? StateName { get; set; } = "";
    public string? CityName { get; set; } = "";
    public string? DestinationName { get; set; } = "";
    public int? minDuration { get; set; } = 0;
    public int? maxDuration { get; set; } = 30;
    public DateTime? startSlots { get; set; } = DateTime.MinValue;
    public DateTime? endSlots { get; set; } = DateTime.MaxValue;
    public int? minAdultPrice { get; set; } = 0;
    public int? maxAdultPrice { get; set; } = 1000000;



    public Dictionary<string, object> ToDictionary()
    {
        var dictionary = new Dictionary<string, object>();

        if (PackageTitle != null) dictionary.Add(nameof(PackageTitle), PackageTitle);
        if (Category != null) dictionary.Add(nameof(Category), Category);
        if (PackageType != null) dictionary.Add(nameof(PackageType), PackageType);
        if (BestSeasion != null) dictionary.Add(nameof(BestSeasion), BestSeasion);
        if (CountryName != null) dictionary.Add(nameof(CountryName), CountryName);
        if (StateName != null) dictionary.Add(nameof(StateName), StateName);
        if (DestinationName != null) dictionary.Add(nameof(DestinationName), DestinationName);

        return dictionary;
    }
}
