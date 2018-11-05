using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using CesviAUTH.Models;
using Microsoft.AspNetCore.Mvc;
using RefreshTokensWebApiExample.DataAccess;
using RefreshTokensWebApiExample.Services;

namespace CesviAUTH.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : Controller
    {
        private readonly UsersDb _usersDb;
        private readonly IPasswordHasher _passwordHasher;
        private readonly ITokenService _tokenService;
        public AccountController(UsersDb usersDb, IPasswordHasher passwordHasher, ITokenService tokenService)
        {
            _usersDb = usersDb;
            _passwordHasher = passwordHasher;
            _tokenService = tokenService;
        }

        // GET api/values
        [HttpGet]
        public ActionResult<IEnumerable<string>> Get()
        {
            return new string[] { "value1", "value2" };
        }



        [HttpPost("signup")]
        public async Task<IActionResult> Signup([FromBody]LoginRequest loginRequest)
        {
            var user = _usersDb.Users.SingleOrDefault(u => u.Username == loginRequest.Username);
            if (user != null) return StatusCode(409);

            _usersDb.Users.Add(new User
            {
                Username = loginRequest.Username,
                Password = _passwordHasher.GenerateIdentityV3Hash(loginRequest.Password)
            });

            await _usersDb.SaveChangesAsync();

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody]LoginRequest loginRequest)
        {
            var user = _usersDb.Users.SingleOrDefault(u => u.Username == loginRequest.Username);
            if (user == null || !_passwordHasher.VerifyIdentityV3Hash(loginRequest.Password, user.Password)) return BadRequest();

            var usersClaims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim("clave", "CV:13456"),
                new Claim("aseguradora", "SURA"),
            };

            var jwtToken = _tokenService.GenerateAccessToken(usersClaims);
            var refreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            await _usersDb.SaveChangesAsync();

            return new ObjectResult(new
            {
                token = jwtToken,
                refreshToken = refreshToken
            });
        }
    }
}