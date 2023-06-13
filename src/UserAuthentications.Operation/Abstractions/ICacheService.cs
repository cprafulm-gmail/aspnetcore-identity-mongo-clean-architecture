using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Operation.Abstractions
{
    public interface ICacheService
    {
        Task SetAsync(string key, string value, TimeSpan duration);
        Task<string> GetAsync(string key);
        Task<bool> RemoveAsync(string key);
    }
}
