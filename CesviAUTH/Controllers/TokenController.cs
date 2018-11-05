using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CesviAUTH.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using RefreshTokensWebApiExample.DataAccess;
using RefreshTokensWebApiExample.Services;

namespace CesviAUTH.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : Controller
    {
        private readonly ITokenService _tokenService;
        private readonly UsersDb _usersDb;
        public TokenController(ITokenService tokenService, UsersDb usersDb)
        {
            _tokenService = tokenService;
            _usersDb = usersDb;
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody]TokenRequest tokenRequest)
        {
            var principal = _tokenService.GetPrincipalFromExpiredToken(tokenRequest.token);
            var username = principal.Identity.Name; //this is mapped to the Name claim by default

            var user = _usersDb.Users.SingleOrDefault(u => u.Username == username);
            if (user == null || user.RefreshToken != tokenRequest.refreshToken) return BadRequest();

            var newJwtToken = _tokenService.GenerateAccessToken(principal.Claims);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _usersDb.SaveChangesAsync();

            return new ObjectResult(new
            {
                token = newJwtToken,
                refreshToken = newRefreshToken
            });
        }

        [HttpPost("revoke"), Authorize]
        public async Task<IActionResult> Revoke()
        {
            var username = User.Identity.Name;

            var user = _usersDb.Users.SingleOrDefault(u => u.Username == username);
            if (user == null) return BadRequest();

            user.RefreshToken = null;

            await _usersDb.SaveChangesAsync();

            return NoContent();
        }
    }
}