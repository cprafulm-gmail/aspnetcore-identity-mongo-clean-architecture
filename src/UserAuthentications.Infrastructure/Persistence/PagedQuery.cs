namespace UserAuthentications.Infrastructure.Persistence;

public class PagedQuery : IPagedQuery
{
    public int Page { get; set; } = 1;
    public int Results { get; set; } = 10;
    //public int PageNumber { get; set; }
    //public int PageSize { get; set; }
    public string OrderBy { get; set; } = "asc";
    public string SortOrder { get; set; } = "";
}
