using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using MongoDB.Driver;

namespace UserAuthentications.Infrastructure.Persistence
{
    public static class Extensions
    {
        public static IServiceCollection AddMongo(this IServiceCollection serviceCollection, string sectionName = "mongo")
        {
            serviceCollection.AddSingleton(sp =>
            {
                var configuration = sp.GetRequiredService<IConfiguration>();
                var model = new MongoDbOptions();
                configuration.GetSection(sectionName).Bind(model);
                return model;
            });

            serviceCollection.AddSingleton(context =>
            {
                var options = context.GetRequiredService<MongoDbOptions>();

                return new MongoClient("mongodb+srv://application_user:iEvWT72cugkO6li2@cluster0.rocwou1.mongodb.net/test"); //("mongodb://localhost:27017");// (options.ConnectionString);
            });

            serviceCollection.AddScoped(context =>
            {
                var options = context.GetRequiredService<MongoDbOptions>();
                var client = context.GetRequiredService<MongoClient>();
                return client.GetDatabase("dejavuTours");// ("DejavuDB");// (options.Database);
            });
            return serviceCollection;
        }

        public static IServiceCollection AddMongoRepository<TEntity>(this IServiceCollection serviceCollection, string collectionName)
            where TEntity : IIdentifiable
        {
            serviceCollection.AddScoped<IMongoRepository<TEntity>>(ctx =>
                new MongoRepository<TEntity>(ctx.GetRequiredService<IMongoDatabase>(), collectionName));
            return serviceCollection;
        }

    }
}