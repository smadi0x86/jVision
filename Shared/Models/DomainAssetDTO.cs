using System.ComponentModel.DataAnnotations;

namespace jVision.Shared.Models
{
    public class DomainAssetDTO
    {
        public int DomainAssetId { get; set; }
        public int? BoxId { get; set; }

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
