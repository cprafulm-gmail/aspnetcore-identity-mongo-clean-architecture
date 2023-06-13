using UserAuthentications.Operation.Abstractions;
using Microsoft.Extensions.Caching.Distributed;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Operation.Implementation
{
    public class CacheService : ICacheService
    {
        private readonly IDistributedCache _distributedCache;

        public CacheService(IDistributedCache distributedCache)
        {
            _distributedCache = distributedCache;
        }

        public async Task SetAsync(string key, string value, TimeSpan duration)
        {
            var options = new DistributedCacheEntryOptions()
                .SetAbsoluteExpiration(DateTime.Now.Add(duration));
            await _distributedCache.SetStringAsync(key, value, options);
        }

        public async Task<string> GetAsync(string key)
        {
            return await _distributedCache.GetStringAsync(key);
        }

        public async Task<bool> RemoveAsync(string key)
        {
            await _distributedCache.RemoveAsync(key);
            return true;
        }
    }
}
