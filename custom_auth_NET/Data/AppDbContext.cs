using Microsoft.EntityFrameworkCore;
using custom_auth_NET.Entities;

namespace custom_auth_NET.Data
{
    public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }
    }
}
