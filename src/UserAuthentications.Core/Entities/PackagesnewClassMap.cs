﻿using UserAuthentications.Core.Entities;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.IdGenerators;
using MongoDB.Bson.Serialization.Serializers;

public class PackagesnewClassMap : BsonClassMap<Packagesnew>
{
    public PackagesnewClassMap()
    {
        MapIdProperty(p => p.Id)
            .SetIdGenerator(StringObjectIdGenerator.Instance)
            .SetSerializer(new StringSerializer(BsonType.ObjectId));
    }
}
