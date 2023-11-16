using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Login_backend
{
    public class ApplicationDbcontext: IdentityDbContext
    {
        public ApplicationDbcontext(DbContextOptions options) : base(options){ }
    }
}
