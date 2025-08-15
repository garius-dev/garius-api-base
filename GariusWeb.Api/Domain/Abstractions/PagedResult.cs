namespace GariusWeb.Api.Domain.Abstractions
{
    public class PagedResult<T>
    {
        public IEnumerable<T> Items { get; set; } = Enumerable.Empty<T>();
        public int TotalCount { get; set; }
        public bool HasNextPage { get; set; }
    }
}
