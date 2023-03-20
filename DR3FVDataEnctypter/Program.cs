using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace DR3FVDataEnctypter;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("错误：参数不足");
        }
        else
        {
            if (!File.Exists(args[0]))
            {
                Console.Error.WriteLine("错误：文件不存在");
            }
            else
            {
                string fileName = Path.Combine(Path.GetDirectoryName(args[0]) ?? throw new InvalidOperationException(), Path.GetFileNameWithoutExtension(args[0]));
                string ext = Path.GetExtension(args[0]).ToLower();
                byte[] bytes, output;
                using (FileStream fileStream = new FileStream(args[0], FileMode.Open, FileAccess.Read)) {
                    bytes = new byte[fileStream.Length];
                    if (fileStream.Read(bytes) != bytes.Length) throw new ArgumentException();
                }
                
                switch (ext)
                {
                    case ".espr":
                        fileName += ".png";
                        try
                        {
                            output = Decode(bytes);
                        }
                        catch (Exception e)
                        {
                            Console.Error.WriteLine(e);
                            Console.Error.WriteLine("错误：文件格式不正确");
                            goto end;
                        }
                        break;
                    case ".jpg":
                    case ".png":
                        fileName += ".espr";
                        output = Encode(bytes);
                        break;
                    default:
                        Console.Error.WriteLine("错误：文件后缀不正确");
                        goto end;
                }

                using (FileStream fileStream = new FileStream(fileName, FileMode.Create, FileAccess.Write))
                {
                    fileStream.Write(output);
                }
                Console.WriteLine("转换成功");
            }
        }

        end:
        Console.WriteLine("请按任意键继续...");
        Console.ReadKey();
    }

    private static string key = "DanceRail3Viewer";
    private static string iv = "PepoyoMyWife2333";

    private static byte[] Encode(byte[] raw)
    {
        if (raw == null || raw.Length <= 0)
            throw new ArgumentNullException(nameof(raw));

        byte[] encrypted;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Encoding.ASCII.GetBytes(key);
            aesAlg.IV = Encoding.ASCII.GetBytes(iv);
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt, Encoding.UTF8))
                    {
                        swEncrypt.Write(Convert.ToBase64String(raw));
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        return encrypted;
    }

    private static byte[] Decode(byte[] data)
    {
        if (data.Length < 1) return Array.Empty<byte>();
        string plaintext;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Encoding.ASCII.GetBytes(key);
            aesAlg.IV = Encoding.ASCII.GetBytes(iv);
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;
            ICryptoTransform descriptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            using (MemoryStream msDecrypt = new MemoryStream(data))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, descriptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return Convert.FromBase64String(plaintext);
    }
}