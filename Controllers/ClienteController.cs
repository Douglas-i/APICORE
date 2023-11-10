using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using APICORE.Models;


using System.Data.SqlClient;
using System.Data;
using Microsoft.AspNetCore.Authorization;

namespace APICORE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ClienteController : ControllerBase
    {

        private readonly string cadenaSQl;

        public ClienteController(IConfiguration config)
        {
            cadenaSQl = config.GetConnectionString("CadenaSQL");

        } 

        [Authorize]
        [HttpGet]
        [Route("Lista")]

        public IActionResult Lista()
        {
            List<Cliente> lista = new List<Cliente>();
            try
            {
                using (var conexion = new SqlConnection(cadenaSQl))
                {

                    conexion.Open();
                    var cmd = new SqlCommand("select * from Clientes", conexion);
                    cmd.CommandType = CommandType.Text;

                    using (var rd = cmd.ExecuteReader())
                    {
                        while (rd.Read())
                        {

                            lista.Add(new Cliente()
                            {
                                IdCliente = Convert.ToInt32(rd["IdCliente"]),
                                Categoria = rd["Categoria"].ToString(),
                                nombreCliente = rd["nombreCliente"].ToString(),
                                apellidoCliente = rd["apellidoCliente"].ToString()


                            });

                        }

                    }

                }
                return StatusCode(StatusCodes.Status200OK, new { mensaje = "Ok", response = lista });

            } catch (Exception error)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { mensaje = error.Message, respuesta = lista });
            }


        }



        [HttpGet]
        [Route("Obtener/{IdCliente:int}")]

        public IActionResult Obtener(int IdCliente)
        {
            List<Cliente> lista = new List<Cliente>();
            Cliente c = new Cliente();
          //  string valor;
            try
            {
                using (var conexion = new SqlConnection(cadenaSQl))
                {

                    conexion.Open();
                    var cmd = new SqlCommand("select * from Clientes", conexion);
                    cmd.CommandType = CommandType.Text;
                    //   var rd = cmd.ExecuteReader();
                    //  valor = rd["nombreCliente"].ToString();

                    using (var rd = cmd.ExecuteReader())
                    {
                        while (rd.Read())
                        {

                            lista.Add(new Cliente()
                            {
                                IdCliente = Convert.ToInt32(rd["IdCliente"]),
                                Categoria = rd["Categoria"].ToString(),
                                nombreCliente = rd["nombreCliente"].ToString(),
                                apellidoCliente = rd["apellidoCliente"].ToString()


                            });

                        }

                    }

                }

                 c = lista.Where(item => item.IdCliente == IdCliente).FirstOrDefault();


                return StatusCode(StatusCodes.Status200OK, new { mensaje = "Ok", response = c});
              //  return StatusCode(StatusCodes.Status200OK, new { mensaje = valor });

            }
            catch (Exception error)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { mensaje = error.Message, respuesta = c });
            }

        }


        [HttpPost]
        [Route("Guardar")]

        public IActionResult Guardar([FromBody] Cliente c)
        {

            try
            {
                using (var conexion = new SqlConnection(cadenaSQl))
                {

                    conexion.Open();
                    var cmd = new SqlCommand("Insert into Clientes(Categoria, nombreCliente, apellidoCliente) " +
                                              "values(@Param1, @Param2, @Param3)", conexion);
                    cmd.Parameters.AddWithValue("@Param1", c.Categoria);
                    cmd.Parameters.AddWithValue("@Param2", c.nombreCliente);
                    cmd.Parameters.AddWithValue("@Param3", c.apellidoCliente);


                    cmd.CommandType = CommandType.Text;
                    cmd.ExecuteNonQuery();



                }



                return StatusCode(StatusCodes.Status200OK, new { mensaje = "Ok" });

            }
            catch (Exception error)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { mensaje = error.Message });
            }


        }
        [Authorize]
        [HttpDelete]
        [Route("Eliminar/{IdCliente:int}")]

        public IActionResult Eliminar(int IdCliente)
        {

            try
            {
                using (var conexion = new SqlConnection(cadenaSQl))
                {

                    conexion.Open();
                    var cmd = new SqlCommand("   delete from Clientes" +
                        "                        where IdCliente = @Param1", conexion);
                    cmd.Parameters.AddWithValue("@Param1", IdCliente);
                 

             

                    cmd.CommandType = CommandType.Text;
                    cmd.ExecuteNonQuery();



                }



                return StatusCode(StatusCodes.Status200OK, new { mensaje = "Eliminado" });

            }
            catch (Exception error)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { mensaje = error.Message });
            }


        }



        [HttpPut]
        [Route("Actualizar/{IdCliente:int}")]

        public IActionResult Editar([FromBody] Cliente c)
        {

            try
            {
                using (var conexion = new SqlConnection(cadenaSQl))
                {

                    conexion.Open();
                    var cmd = new SqlCommand("   Update Clientes set Categoria = @Param1, nombreCliente = @Param2," +
                        "                        apellidoCliente = @param3" +
                        "                        where IdCliente = @Param4", conexion);
                    cmd.Parameters.AddWithValue("@Param1", c.Categoria);
                    cmd.Parameters.AddWithValue("@Param2", c.nombreCliente);
                    cmd.Parameters.AddWithValue("@Param3", c.apellidoCliente);
                    cmd.Parameters.AddWithValue("@Param4", c.IdCliente);


                    //cmd.Parameters.AddWithValue("@Param1", c.Categoria is null ? DBNull.Value : c.Categoria);
                    //cmd.Parameters.AddWithValue("@Param2", c.nombreCliente is null ? DBNull.Value : c.nombreCliente);
                    //cmd.Parameters.AddWithValue("@Param3", c.apellidoCliente is null ? DBNull.Value : c.apellidoCliente);
                    //cmd.Parameters.AddWithValue("@Param4", c.IdCliente == 0 ? DBNull.Value : c.IdCliente);



                    cmd.CommandType = CommandType.Text;
                    cmd.ExecuteNonQuery();



                }



                return StatusCode(StatusCodes.Status200OK, new { mensaje = "Editado" });

            }
            catch (Exception error)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { mensaje = error.Message });
            }


        }

    }
}
