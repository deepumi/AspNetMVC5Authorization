using Newtonsoft.Json;

namespace AspNetMVC5Authorization.Helpers
{
    public static class JsonSerializer
    {
        public static string ToJson<T>(this T t)
        {
            return JsonConvert.SerializeObject(t);
        }

        public static T ToObject<T>(this string data)
        {
            return JsonConvert.DeserializeObject<T>(data);
        }
    }
}