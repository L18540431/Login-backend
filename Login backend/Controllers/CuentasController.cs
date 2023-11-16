using Login_backend.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Login_backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CuentasController : Controller
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly IConfiguration configuration;
        private readonly SignInManager<IdentityUser> signInManager;

        public CuentasController(UserManager<IdentityUser> userManager,
            IConfiguration configuration,
            SignInManager<IdentityUser> signInManager) 
        {
            this.userManager = userManager;
            this.configuration = configuration;
            this.signInManager = signInManager;
        }
        [HttpPost("registrar")]
        public async Task<ActionResult<RespuestaAutenticacion>> Registrar(CredencialesUsuarios credencialesUsuarios)
        {
            var usuario = new IdentityUser
            {
                UserName = credencialesUsuarios.Email,
                Email = credencialesUsuarios.Email,
            };
            var resultado = await userManager.CreateAsync(usuario,credencialesUsuarios.Password);
            if(resultado.Succeeded)
            {
                return await ContruirToken(credencialesUsuarios);
            }
            return BadRequest(resultado.Errors);
        }
        private async Task<RespuestaAutenticacion> ContruirToken(CredencialesUsuarios credencialesUsuarios) 
        {
            var claims = new List<Claim>()
            {
                new Claim("email", credencialesUsuarios.Email),
            };
            var usuario = await userManager.FindByEmailAsync(credencialesUsuarios.Email);
            var claimsRoles = await userManager.GetClaimsAsync(usuario);

            claims.AddRange(claims);
            
            var llave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["LlaveJWT"]));
            var creds = new SigningCredentials(llave, SecurityAlgorithms.HmacSha256);
            
            var expiracion = DateTime.UtcNow.AddDays(1);

            var securityToken = new JwtSecurityToken(issuer: null, audience: null,
                claims: claims, expires: expiracion,signingCredentials: creds);

            return new RespuestaAutenticacion
            {
                Token = new JwtSecurityTokenHandler().WriteToken(securityToken),
                Expiracion = expiracion,
            };
        }
        [HttpGet("RenovarToken")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult<RespuestaAutenticacion>> Renovar()
        {
            var emailClaim = HttpContext.User.Claims.Where(x => x.Type == "email").FirstOrDefault();
            var credencialesUsuario = new CredencialesUsuarios()
            {
                Email = emailClaim.Value
            };
            return await ContruirToken(credencialesUsuario);
        }

    }
}
