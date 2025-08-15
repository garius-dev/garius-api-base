using GariusWeb.Api.Domain.Abstractions;
using GariusWeb.Api.Domain.Interfaces;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace GariusWeb.Api.Infrastructure.Data.Repositories
{
    public class GenericRepository<T> : IGenericRepository<T> where T : class, IBaseEntity
    {
        private readonly ApplicationDbContext _context;
        private readonly DbSet<T> _dbSet;

        public GenericRepository(ApplicationDbContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
            _dbSet = _context.Set<T>();
        }

        public async Task<PagedResult<T>> GetPagedAsync(
        int pageSize,
        Guid? lastId,
        Expression<Func<T, bool>>? filter = null,
        CancellationToken cancellationToken = default)
        {
            var query = _dbSet.AsNoTracking().OrderBy(e => e.Id);

            if (filter != null)
            {
                query = (IOrderedQueryable<T>)query.Where(filter);
            }

            var totalCount = await query.CountAsync(cancellationToken);

            if (lastId.HasValue)
            {
                query = (IOrderedQueryable<T>)query.Where(e => e.Id.CompareTo(lastId.Value) > 0);
            }

            var items = await query
                .Take(pageSize + 1)
                .ToListAsync(cancellationToken);

            var hasNextPage = items.Count > pageSize;
            var resultItems = items.Take(pageSize);

            return new PagedResult<T>
            {
                Items = resultItems,
                TotalCount = totalCount,
                HasNextPage = hasNextPage
            };
        }
    }
}