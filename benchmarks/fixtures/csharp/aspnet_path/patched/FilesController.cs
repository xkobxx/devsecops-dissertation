// Patched benchmark equivalent with canonical root confinement.
using Microsoft.AspNetCore.Mvc;

[ApiController]
public sealed class FilesController : ControllerBase
{
    [HttpGet("/files")]
    public ActionResult<string> Read([FromQuery] string name)
    {
        string root = System.IO.Path.GetFullPath("/srv/files") + System.IO.Path.DirectorySeparatorChar;
        string candidate = System.IO.Path.GetFullPath(System.IO.Path.Combine(root, name));
        if (!candidate.StartsWith(root, System.StringComparison.Ordinal)) return BadRequest();
        return System.IO.File.ReadAllText(candidate);
    }
}
