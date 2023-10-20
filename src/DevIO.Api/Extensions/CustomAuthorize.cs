using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace DevIO.Api.Extensions
{
    public class CustomAuthorization
    {
        public static bool ValidarClaimsUsuario(HttpContext context, string claimName, string claimValue) // contexto // NomeClaim Fornecedor / claimValue é tipo de autorização
        {
            return context.User.Identity.IsAuthenticated && // verifica se esta autenticado
                   context.User.Claims.Any(c => c.Type == claimName && c.Value.Contains(claimValue)); // verifica se tem alguma claim com base acima
        }

    }

    public class ClaimsAuthorizeAttribute : TypeFilterAttribute //
    {
        public ClaimsAuthorizeAttribute(string claimName, string claimValue) : base(typeof(RequisitoClaimFilter)) // seta uma base Nova com a função abaixo 
        {
            Arguments = new object[] { new Claim(claimName, claimValue) };
        }
    }

    public class RequisitoClaimFilter : IAuthorizationFilter
    {
        private readonly Claim _claim;

        public RequisitoClaimFilter(Claim claim)
        {
            _claim = claim;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.User.Identity.IsAuthenticated) // verifica se está autenticado 
            {
                context.Result = new StatusCodeResult(401); // usuario desconhecido 
                return;
            }

            if (!CustomAuthorization.ValidarClaimsUsuario(context.HttpContext, _claim.Type, _claim.Value)) // eu sei quem é o usuario, mas ele não tem permissão para isso
            {
                context.Result = new StatusCodeResult(403);
            }
        }
    }
}