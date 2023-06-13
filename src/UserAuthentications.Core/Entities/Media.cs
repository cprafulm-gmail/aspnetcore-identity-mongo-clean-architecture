using System.ComponentModel.DataAnnotations;
using UserAuthentications.Infrastructure.Persistence;

namespace UserAuthentications.Core.Entities
{
    public class Media : IIdentifiable
    {
        public string? Id { get; set; }
        public string Name { get; set; }
        public string Extension { get; set; }
        public string ContentType { get; set; }
        public byte[] Data { get; set; }
        public string FileToRemove { get; set; }
        public string s3Folder { get; set; }
    }
}
