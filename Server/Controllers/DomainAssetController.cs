using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using jVision.Server.Data;
using jVision.Server.Models;
using jVision.Shared.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace jVision.Server.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class DomainAssetController : ControllerBase
    {
        private readonly JvisionServerDBContext _context;

        public DomainAssetController(JvisionServerDBContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<DomainAssetDTO>>> GetDomainAssets()
        {
            return await _context.DomainAssets
                .Select(d => DomainAssetToDTO(d))
                .ToListAsync();
        }

        [HttpPost]
        public async Task<IActionResult> PostDomainAssets(IList<DomainAssetDTO> assets)
        {
            if (assets == null || !assets.Any())
            {
                return BadRequest("No assets supplied");
            }

            foreach (var assetDto in assets)
            {
                var entity = await _context.DomainAssets
                    .FirstOrDefaultAsync(a => a.Hostname == assetDto.Hostname && a.DomainName == assetDto.DomainName);

                if (entity == null)
                {
                    entity = new DomainAsset();
                    _context.DomainAssets.Add(entity);
                }

                UpdateEntity(entity, assetDto);
            }

            await _context.SaveChangesAsync();
            return Ok();
        }

        private void UpdateEntity(DomainAsset entity, DomainAssetDTO dto)
        {
            entity.Hostname = dto.Hostname;
            entity.DomainName = dto.DomainName;
            entity.DistinguishedName = dto.DistinguishedName;
            entity.Role = dto.Role;
            entity.Ip = dto.Ip;
            entity.IsDomainController = dto.IsDomainController;
            entity.Notes = dto.Notes;

            if (dto.BoxId.HasValue)
            {
                entity.BoxId = dto.BoxId;
            }
            else if (!string.IsNullOrWhiteSpace(dto.Ip))
            {
                var linkedBox = _context.Boxes.FirstOrDefault(b => b.Ip == dto.Ip);
                entity.BoxId = linkedBox?.BoxId;
            }
            else
            {
                entity.BoxId = null;
            }
        }

        private static DomainAssetDTO DomainAssetToDTO(DomainAsset d) =>
            new DomainAssetDTO
            {
                DomainAssetId = d.DomainAssetId,
                BoxId = d.BoxId,
                Hostname = d.Hostname,
                DomainName = d.DomainName,
                DistinguishedName = d.DistinguishedName,
                Role = d.Role,
                Ip = d.Ip,
                IsDomainController = d.IsDomainController,
                Notes = d.Notes
            };
    }
}
