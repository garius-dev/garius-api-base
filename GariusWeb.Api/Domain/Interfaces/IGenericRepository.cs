using GariusWeb.Api.Domain.Abstractions;
using System.Linq.Expressions;

namespace GariusWeb.Api.Domain.Interfaces
{
    public interface IGenericRepository<T> where T : class, IBaseEntity
    {
        Task<PagedResult<T>> GetPagedAsync(
            int pageSize,
            Guid? lastId,
            Expression<Func<T, bool>>? filter = null,
            CancellationToken cancellationToken = default);
    }
}