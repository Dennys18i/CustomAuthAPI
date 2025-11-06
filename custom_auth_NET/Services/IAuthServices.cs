using custom_auth_NET.Entities;
using custom_auth_NET.Models;

namespace custom_auth_NET.Services
{
    public interface IAuthServices
    {
        Task<User?> RegisterAsync(UserDto request);
        Task<string?> LoginAsync(UserDto request);
    }
}
