using BackendAuthDemo.Context;
using BackendAuthDemo.Helpers;
using BackendAuthDemo.Models;
using BackendAuthDemo.Models.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
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
        private readonly IJWTTokenService _jwtService;
        public UserController(AppDbContext authContext, IJWTTokenService jwtService)
        {
            _authContext = authContext;
            _jwtService = jwtService;
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

            userDb.Token = _jwtService.CreateJwt(userDb);
            var newAccessToken = userDb.Token;
            var newRefreshToken = _jwtService.CreateRefreshToken(_authContext.Users);
            userDb.RefreshToken = newRefreshToken;
            userDb.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
            // need to save refresh token and user token values in db
            await _authContext.SaveChangesAsync();

            return Ok(
                    new TokenApiDTO
                    {
                        AccessToken = newAccessToken,
                        RefreshToken = userDb.RefreshToken
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

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDTO tokenApiDto)
        {
            if (tokenApiDto is null)
                return BadRequest("Invalid Client Request");
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principal = _jwtService.GetPrincipleFromExpiredToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                return BadRequest("Invalid Request");
            var newAccessToken = _jwtService.CreateJwt(user);
            var newRefreshToken = _jwtService.CreateRefreshToken(_authContext.Users);
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDTO()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });
        }

        #endregion

    }

}
