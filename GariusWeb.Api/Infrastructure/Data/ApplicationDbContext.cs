﻿using GariusWeb.Api.Domain.Entities.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace GariusWeb.Api.Infrastructure.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>(b =>
            {
                b.Property(p => p.FirstName).HasMaxLength(100).IsRequired();
                b.Property(p => p.LastName).HasMaxLength(100).IsRequired();
            });

            builder.Entity<ApplicationRole>(b =>
            {
                b.Property(p => p.Description).HasMaxLength(250);
            });
        }
    }
}
