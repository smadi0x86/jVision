using System.ComponentModel.DataAnnotations;

namespace jVision.Server.Models
{
    public class DomainAsset
    {
        public int DomainAssetId { get; set; }

        public int? BoxId { get; set; }
        public Box Box { get; set; }

        [Required]
        public string Hostname { get; set; }
        public string DomainName { get; set; }
        public string DistinguishedName { get; set; }
        public string Role { get; set; }
        public string Ip { get; set; }
        public bool IsDomainController { get; set; }
        public string Notes { get; set; }
    }
}
