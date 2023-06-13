using System.Text.Json.Serialization;

namespace UserAuthentications.Infrastructure.Persistence;


public class PagedResult<T> : PagedResultBase
{
    public IEnumerable<T> Items { get; }
    public decimal MaxTotalAmount { get; }

    public bool IsEmpty => Items is null || !Items.Any();
    public bool IsNotEmpty => !IsEmpty;
    public IDictionary<string, object> AppliedFilter { get; }

    protected PagedResult()
    {
        Items = Enumerable.Empty<T>();
        MaxTotalAmount = 0;
        AppliedFilter = new PackageFilterQery().ToDictionary();
        //AppliedFilter = new PackageFilterQery();

    }

    [JsonConstructor]
    protected PagedResult(IEnumerable<T> items, decimal maxTotalAmount,
        int currentPage, int resultsPerPage,
        int totalPages, long totalResults,
            IDictionary<string, object> appliedFilter) :
        base(currentPage, resultsPerPage, totalPages, totalResults)
    {
        Items = items;
        MaxTotalAmount = maxTotalAmount;
        AppliedFilter = appliedFilter;
    }

    public static PagedResult<T> Create(IEnumerable<T> items, decimal maxTotalAmount,
        int currentPage, int resultsPerPage,
        int totalPages, long totalResults )
        => new(items, maxTotalAmount, currentPage, resultsPerPage, totalPages, totalResults, new Dictionary<string, object>());

    public static PagedResult<T> From(PagedResultBase result, IEnumerable<T> items, decimal maxTotalAmount, PackageFilterQery filter)
        => new(items, maxTotalAmount, result.CurrentPage, result.ResultsPerPage,
            result.TotalPages, result.TotalResults,
        filter.ToDictionary());

    public static PagedResult<T> Empty => new();

    public PagedResult<U> Map<U>(Func<T, U> map)
        => PagedResult<U>.From(this, Items.Select(map), MaxTotalAmount, new PackageFilterQery());
}