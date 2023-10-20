namespace DevIO.Api.Extensions
{
    public class AppSettings
    {
        public string Secret { get; set; } // chave de criptografia
        public int ExpiracaoHoras { get; set; } // tempo de duração do token 
        public string Emissor { get; set; } // quem emite tipo minha aplicação
        public string ValidoEm { get; set; } // quais urls esse token é valido 
    }
}