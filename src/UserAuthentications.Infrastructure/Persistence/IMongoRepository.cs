using System.Linq.Expressions;

namespace UserAuthentications.Infrastructure.Persistence
{
    public interface IMongoRepository<TEntity> where TEntity : IIdentifiable
    {
        Task<IEnumerable<TEntity>> GetAllAsync();
        Task<TEntity> GetAsync(string id);
         Task<TEntity> GetAsync(Expression<Func<TEntity, bool>> predicate);
         Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate);
         Task<PagedResult<TEntity>> BrowseAsync<TQuery>(Expression<Func<TEntity, bool>> predicate,
				TQuery query) where TQuery : IPagedQuery;
         Task AddAsync(TEntity entity);
         Task UpdateAsync(TEntity entity);
         Task DeleteAsync(string id); 
         Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> predicate);
    }
}