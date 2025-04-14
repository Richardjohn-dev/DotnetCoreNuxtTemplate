using Backend.Infrastructure.Persistence.Entity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Backend.Infrastructure.Persistence;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<ApplicationUser> Users { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }


    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        // Configure RefreshToken entity
        builder.Entity<RefreshToken>(entity =>
        {
            // Index on the token value for faster lookups
            entity.HasIndex(rt => rt.Token).IsUnique();

            // Relationship with ApplicationUser
            entity.HasOne(rt => rt.User)
                  .WithMany() // Assuming a user can have multiple tokens over time, but maybe only one active?
                  .HasForeignKey(rt => rt.UserId)
                  .IsRequired()
                  .OnDelete(DeleteBehavior.Cascade); // Delete refresh tokens if user is deleted

            // Configure Token property if needed (e.g., max length)
            entity.Property(rt => rt.Token).IsRequired().HasMaxLength(256); // Adjust length as needed
            entity.Property(rt => rt.JwtId).IsRequired().HasMaxLength(256);
        });
    }
}

// create a migration
// dotnet ef migrations add "Intial IdentityDb" -o "Infrastructure/Persistence/Migrations"