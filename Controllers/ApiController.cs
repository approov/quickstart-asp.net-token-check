using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace NetCoreJWTAuth.App.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api")]
    public class ApiController : Controller
    {
        private readonly IConfiguration _configuration;

        public ApiController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("Test")]
        public IActionResult Test()
        {
            return Ok("Super secret content, I hope you've got clearance for this...");
        }

    }
}