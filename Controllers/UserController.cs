using BackendAuthDemo.Context;
using BackendAuthDemo.Helpers;
using BackendAuthDemo.Models;
using BackendAuthDemo.Models.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace BackendAuthDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext authContext)
        {
            _authContext = authContext;
        }
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate(User user)
        {
            if (user == null)
                return BadRequest("user is null!");
            var userDb = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName.Trim().ToLower() == user.UserName.Trim().ToLower());

            if (null == userDb)
                return NotFound(new { Message = "User is not found!" });
            if (!EncryptPassword.VerifyPassword(user.Password, userDb.Password))
                return NotFound(new { Message = "Password does not match!" });

            user.Token = CreateJwt(userDb);
            var newAccessToken = user.Token;
            user.RefreshToken = CreateRefreshToken();

            // need to save refresh token and user token values in db
            await _authContext.SaveChangesAsync();

            return Ok(
                    new TokenApiDTO
                    {
                        AccessToken = newAccessToken,
                        RefreshToken = user.RefreshToken
                    });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser(User user)
        {
            if (user == null)
                return BadRequest(new { Message = "user is null!" });
            if (user != null && (string.IsNullOrWhiteSpace(user.UserName) || string.IsNullOrWhiteSpace(user.Password)))
                return BadRequest(new { Message = "username or password required!" });
            if (await UserExists(user.UserName))
                return BadRequest(new { Message = $"user {user.UserName} already exists!" });
            if (await EmailExists(user.Email))
                return BadRequest(new { Message = $"email {user.Email} already exists!" });
            var pass = CheckPasswordLength(user.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass });

            user.Password = EncryptPassword.HashPassword(user.Password);
            user.Role = "user";
            user.Token = "";
            await _authContext.Users.AddAsync(user);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User was registered successfully!" });
        }
        [Authorize]
        [HttpGet("users")]
        public async Task<IActionResult> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }

        private async Task<bool> UserExists(string userName)
            => await _authContext.Users.AnyAsync(u => u.UserName.Trim().ToLower() == userName.Trim().ToLower());

        private async Task<bool> EmailExists(string email)
            => await _authContext.Users.AnyAsync(u => u.Email.Trim().ToLower() == email.Trim().ToLower());

        private string CheckPasswordLength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 9)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be AlphaNumeric" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password should contain special charcter" + Environment.NewLine);

            return sb.ToString();
        }

        #region token

        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysceret.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name,$"{user.UserName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(600),
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        private string CreateRefreshToken()
        {
            var tokenInt = System.Security.Cryptography.RandomNumberGenerator.GetInt32(64);
            var refreshToken = Convert.ToBase64String(new byte[tokenInt]);

            var tokenInUser = _authContext.Users
                .Any(a => a.RefreshToken == refreshToken);
            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }

        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverysceret.....");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("This is Invalid Token");
            return principal;
        }

        #endregion
    }
}