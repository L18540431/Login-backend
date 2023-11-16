namespace Login_backend.Models
{
    public class RespuestaAutenticacion
    {
        public String Token { get; set; }
        public DateTime Expiracion { get; set; }
    }
}
