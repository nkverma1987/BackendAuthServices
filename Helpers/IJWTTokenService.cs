using BackendAuthDemo.Models;
using System.Collections.Generic;
using System.Security.Claims;

namespace BackendAuthDemo.Helpers
{
    public interface IJWTTokenService
    {
        string CreateJwt(User user);
        string CreateRefreshToken(IEnumerable<User> users);
        ClaimsPrincipal GetPrincipleFromExpiredToken(string token);
    }
}

