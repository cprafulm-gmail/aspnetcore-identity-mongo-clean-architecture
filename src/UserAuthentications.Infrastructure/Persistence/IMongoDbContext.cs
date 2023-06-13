using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UserAuthentications.Infrastructure.Persistence
{
    public interface IMongoDbContextd
    {
        IMongoCollection<T> GetCollection<T>(string name);
    }
}
