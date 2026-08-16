// Deliberately vulnerable benchmark fixture. Do not deploy.
using Microsoft.AspNetCore.Mvc;

[ApiController]
public sealed class FilesController : ControllerBase
{
    [HttpGet("/files")]
    public string Read([FromQuery] string name) =>
        System.IO.File.ReadAllText(System.IO.Path.Combine("/srv/files", name));
}
