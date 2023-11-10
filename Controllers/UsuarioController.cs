using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using APICORE.Models;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Data.SqlClient;
using System.Data;
using System.Security.Claims;
using System.Security.Cryptography;

namespace APICORE.Controllers
{      
        [Route("api/[controller]")]
        [ApiController]
    public class UsuarioController : ControllerBase
    {
      
        private IConfiguration _config;
        private readonly string cadenaSQl;

        public UsuarioController(IConfiguration configuration)
        {
            _config = configuration;
            cadenaSQl = configuration.GetConnectionString("CadenaSQL");
        }


        private string GenerateToken()
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(_config["Jwt:Issuer"], _config["Jwt:Audience"], null,
                expires: DateTime.Now.AddMinutes(5), signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);

        }


        //Aqui va lo mio
        [HttpPost]
        public IActionResult Postprueba(Users usuario)
        {
            string rol = "";
            string tokenString = "";
            string estado = "";
            string nombre = "";

            try
            {
                using (var connection = new SqlConnection(cadenaSQl))
                {
                    connection.Open();
                    var query = "ValidarLogin";
                    using (var command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.StoredProcedure;
                        command.Parameters.AddWithValue("@nombre_usuario", usuario.UserName);
                        command.Parameters.AddWithValue("@contrasenia", usuario.Password);
                        using (var reader = command.ExecuteReader())
                        {
                            if (reader.Read())
                            {
                                estado = reader["estado"].ToString().Trim();

                                if (estado == "Inicio de sesión fallido")
                                    return BadRequest(new { mensaje = "Usuario o contraseña incorrectos" });
                                else if( estado == "Usuario deshabilitado")
                                    return BadRequest(new { mensaje = "Usuario deshabilitado" });
                                else
                                {
                                    rol = reader["rol"].ToString().Trim();
                                    nombre = reader["usuario"].ToString().Trim();
                                    var token = GenerateToken();
                                    tokenString = token;
                                }
                            }
                        }
                    }
                }

                return Ok(new { nomnbre = nombre, rol = rol, estado = estado, token = tokenString });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = ex.Message});
            }
        }
    }

}

