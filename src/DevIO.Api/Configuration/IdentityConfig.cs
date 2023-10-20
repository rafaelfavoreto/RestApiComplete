using System.Text;
using DevIO.Api.Data;
using DevIO.Api.Extensions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace DevIO.Api.Configuration
{
    public static class IdentityConfig
    {
        public static IServiceCollection AddIdentityConfiguration(this IServiceCollection services,
            IConfiguration configuration)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

            services.AddDefaultIdentity<IdentityUser>()
                .AddRoles<IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddErrorDescriber<IdentityMensagensPortugues>()
                .AddDefaultTokenProviders();

            // JWT

            var appSettingsSection = configuration.GetSection("AppSettings");
            services.Configure<AppSettings>(appSettingsSection);

            var appSettings = appSettingsSection.Get<AppSettings>();
            var key = Encoding.ASCII.GetBytes(appSettings.Secret);

            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // cria o token 
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme; // verifica se existe o token
            }).AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = true; // para garantir que seja Https
                x.SaveToken = true; // para guardar httpAutentication props
                x.TokenValidationParameters = new TokenValidationParameters  
                {
                    ValidateIssuerSigningKey = true, // validar quem está emtindo é o mesmo que recebe , baseado na chave e no nome
                    IssuerSigningKey = new SymmetricSecurityKey(key), // tranforma em uma chave criptografada
                    ValidateIssuer = true, // valida apenas o emissor da chave nome
                    ValidateAudience = true, // a onde esse token é valido, "ValidoEm" nesse caso
                    ValidAudience = appSettings.ValidoEm, // setando a audiencia 
                    ValidIssuer = appSettings.Emissor // setando o emissor 
                };
            });

            return services;
        }
    }
}