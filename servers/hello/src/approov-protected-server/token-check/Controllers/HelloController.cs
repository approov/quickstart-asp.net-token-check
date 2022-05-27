using Microsoft.AspNetCore.Mvc;

namespace Hello.Controllers;

[ApiController]
[Produces("application/json")]
[Route("/")]
public class HelloController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public HelloController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpGet]
    public IActionResult Get()
    {
        return Ok( new { message = "Hello, World!" } );
    }
}
