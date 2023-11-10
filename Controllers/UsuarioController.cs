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

        // [AllowAnonymous]
        //[HttpPost]
        //public IActionResult Login([FromBody] Users usuario)
        //{

        //    IActionResult response = Unauthorized();
        //    var user_ = AuthenticateUser(usuario.UserName, usuario.Password);
        //    if (user_ != null)
        //    {

        //        var token = GenerateToken();
        //        response = Ok(new { token = token, user_ });

        //    }
        //    return response;
        //}

        //private Users AuthenticateUser(string nombreUsuario, string password)
        //{
        //    string rol = "";
        //    Users usuario = new Users();
        //    try
        //    {
        //        using (var connection = new SqlConnection(cadenaSQl))
        //        {
        //            connection.Open();
        //            var cmd = new SqlCommand("usp_ValidarUsuario", connection);
        //            cmd.CommandType = CommandType.StoredProcedure;

        //            cmd.Parameters.AddWithValue("@usuario", nombreUsuario);
        //            cmd.Parameters.AddWithValue("@contraseña", password);

        //            using (var reader = cmd.ExecuteReader())
        //            {
        //                while (reader.Read())
        //                {
        //                    usuario.UserName = reader["ROL"].ToString();
        //                    usuario.Password = reader["Password"].ToString();
        //                }
        //            }
        //        }
        //        return usuario;

        //    }
        //    catch (Exception ex)
        //    {
        //        return usuario = null;
        //    }

        //}

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
                            //if (reader[5].ToString() == "Activo" || reader[0].ToString() == "Inicio de sesión fallido")
                            //{
                            //    rol = reader["rol"].ToString();
                            //    var token = GenerateToken();
                            //    tokenString = token;
                            //    estado = reader["Estado"].ToString();
                            //}
                            //else if (reader["Mensaje"].ToString() == "Usuario deshabilitado")
                            //{
                            //    return BadRequest(new { mensaje = "Usuario deshabilitado" });
                            //} else
                            //{
                            //    return BadRequest(new { mensaje = "Usuario o contraseña incorrectos" });
                            //}
                            if (reader.Read())
                            {
                                estado = reader["Estado"].ToString();

                                if (estado == "Activo")
                                {
                                    rol = reader["rol"].ToString();
                                    var token = GenerateToken();
                                    tokenString = token;

                                }
                                else if (reader["Mensaje"].ToString() == "Usuario deshabilitado")
                                {
                                    return BadRequest(new { mensaje = "Usuario deshabilitado" });
                                }

                                //rol = reader["rol"].ToString();
                                //var token = GenerateToken();
                                //tokenString = token;
                            }
                            else
                            {
                                return BadRequest(new { mensaje = "Usuario o contraseña incorrectos" });
                            }
                        }
                    }
                }

                return Ok(new { rol = rol, estado = estado, token = tokenString });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { mensaje = "Entro al catch" });
            }
        }
    }

}

