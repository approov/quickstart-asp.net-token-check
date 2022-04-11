using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace NetCoreJWTAuth.App.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/test")]
    public class ApiController : Controller
    {
        private readonly IConfiguration _configuration;

        public ApiController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet]
        public JsonResult Get()
        {
            return Json( new { message = "Super secret content, I hope you've got clearance for this..." } );
        }
    }
}
