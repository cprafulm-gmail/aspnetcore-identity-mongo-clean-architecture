using System;
using System.Linq.Expressions;
using System.Text;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.Linq;

namespace UserAuthentications.Infrastructure.Persistence
{
    public class MongoRepository<TEntity> : IMongoRepository<TEntity> where TEntity : IIdentifiable
    {
        protected IMongoCollection<TEntity> Collection { get; }

		public MongoRepository(IMongoDatabase database, string collectionName)
		{
			Collection = database.GetCollection<TEntity>(collectionName);
		}
        public async Task<IEnumerable<TEntity>> GetAllAsync()
        {
            return await Collection.Find(_ => true).ToListAsync();
        }

        public async Task<TEntity> GetAsync(string id)
            => await GetAsync(e => e.Id == id);

        public async Task<TEntity> GetAsync(Expression<Func<TEntity, bool>> predicate)
            => await Collection.Find(predicate).SingleOrDefaultAsync();

        public async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate)
            => await Collection.Find(predicate).ToListAsync();

        public async Task<PagedResult<TEntity>> BrowseAsync<TQuery>(Expression<Func<TEntity, bool>> predicate,
				TQuery query) where TQuery : IPagedQuery
			=> await Collection.AsQueryable().Where(predicate).PaginateAsync(query);

		public async Task AddAsync(TEntity entity)
			=> await Collection.InsertOneAsync(entity);

		public async Task UpdateAsync(TEntity entity)
			=> await Collection.ReplaceOneAsync(e => e.Id == entity.Id, entity);

		public async Task DeleteAsync(string id)
			=> await Collection.DeleteOneAsync(e => e.Id == id);

		public async Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> predicate)
			=> await Collection.Find(predicate).AnyAsync();

        public async Task<decimal> GetTotalAmountAsync()
        {
            //return await Collection.SumAsync(x => ((dynamic)x).TotalAmount);
            var result = await Collection.Aggregate()
                .Group(new BsonDocument { { "_id", null }, { "total", new BsonDocument("$sum", "$totalAmount") } })
                .FirstOrDefaultAsync();

            return result == null ? 0 : result["total"].ToDecimal();
        }
        private bool VerifyPassword(string password, string hashedPassword)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != hashedPassword[i]) return false;
                }
            }
            return true;
        }
    }
}