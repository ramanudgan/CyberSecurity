
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System.Security.Cryptography;
using System.Text;
class Program 
{
    public static void Main(string[] args)
    {
        RSA();
        BlowFish();
        AES();
    }

    public static void AES()
    {
        Console.Write("Input string to encrypt: ");
        var text = Console.ReadLine();
        // создаём шифр
        using System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
        // генерируем ключ или используем свой ключ с помощью aes.Key = my_key; aes.IV = my_iv
        aes.GenerateKey();
        // зашифровываем данные с помощью режима сцепления блоков CBC и случайного числа(aes.IV)
        var ecryptedArray = aes.EncryptCbc(Encoding.UTF8.GetBytes(text), aes.IV);
        var encryptedText = Encoding.UTF8.GetString(ecryptedArray);
        // расшифровываем данные
        var decryptedText = Encoding.UTF8.GetString(aes.DecryptCbc(ecryptedArray, aes.IV));

        Console.WriteLine($"Open text: {text}");
        Console.Write("Key: ");
        foreach(var bt in aes.Key) Console.Write($"{bt.ToString()} ");
        Console.WriteLine();
        Console.Write("IV(initialization vector): ");
        foreach (var bt in aes.IV) Console.Write($"{bt.ToString()} ");
        Console.WriteLine();
        Console.WriteLine($"Encrypred text: {encryptedText}");
        Console.WriteLine($"Decrypted text: {decryptedText}");
    }

    public static void BlowFish()
    {
        string text = "Привет, я читал канал VT_InfoSecurity";
        var key = Encoding.UTF8.GetBytes("Я есть ключ");
        // Создаём шифр и получаем размер блока. Размер блока покажет
        // Количество шифруемых байт за раз
        BlowfishEngine engine = new BlowfishEngine();
        int blockSize = engine.GetBlockSize(); // = 8 байт
        // Подумайте, почему выбрали массивы длинной 1024?
        byte[] openText = new byte[1024];
        byte[] encryptedBuffer = new byte[1024];
        byte[] decryptedBuffer = new byte[1024];
        // Копируем текст в массив байт (занимает 54 байта)
        Encoding.UTF8.GetBytes(text).CopyTo(openText, 0);
        // Создаём ключ и инициализируем шифр в режиме шифрования
        var keyParam = new KeyParameter(key);
        engine.Init(true, keyParam);
        // Разбиваем openText на блоки,длинна которых равна длинне ключа
        // Начинаем шифровать данные с первого блока
        // Когда блок успешно зашифрован, ProcessBlock возвращает количество зашифрованных байт
        // На каждой итерации делаем смещение относительно начального положения на количество зашифрованных байт
        // Шифруем, пока все блоки не будут зашифрованы
        int i = 0;
        while (i < openText.Length)
        {
            i += engine.ProcessBlock(openText, i, encryptedBuffer, i);
        }
        // Задаём режим дешифрования
        engine.Init(false, keyParam);
        // Блоками дешифруем
        i = 0;
        while(i < encryptedBuffer.Length)
        {
            i += engine.ProcessBlock(encryptedBuffer, i, decryptedBuffer, i);
        }
        var decryptedText = Encoding.UTF8.GetString(encryptedBuffer);
    }

    public static void RSA()
    {
        string text = "Привет, я читаю канал VT_InfoSecurity";
        byte[] openText = Encoding.UTF8.GetBytes(text);
        // Моделируем ситуацию отправитель - получатель
        // Создаём "отправителя"
        using System.Security.Cryptography.RSACryptoServiceProvider rsaProvider_Sender = new RSACryptoServiceProvider();
        // Создаём "получателя"
        using System.Security.Cryptography.RSACryptoServiceProvider rsaProvider_Receiver = new RSACryptoServiceProvider();
        // Создаём "злоумышленника"
        using System.Security.Cryptography.RSACryptoServiceProvider rsaProvider_Attacker = new RSACryptoServiceProvider();
        // получатель сообщает отправителю свой публичный ключ
        var publicKey = rsaProvider_Receiver.ToXmlString(false);
        rsaProvider_Sender.FromXmlString(publicKey);
        // Отправитель шифрует данные с помощью публичного ключа получателя
        var sendData = rsaProvider_Sender.Encrypt(openText, false);
        var senderText = Encoding.UTF8.GetString(sendData);
        try
        {
            // Злоумышленник увидел открытый ключ
            // Теперь он будет пытаться с помощью открытого ключа расшифровать шифртекст
            // Если бы это было симметричное шифрование, то у него бы всё получилось
            // но у нас асиметричное
            rsaProvider_Attacker.FromXmlString(publicKey);
            var sender_decrypt_data = rsaProvider_Attacker.Decrypt(sendData, false);
        }catch(CryptographicException ex)
        {
            Console.WriteLine(ex.Message);
        }
        // Получатель расшифровывает данные своим публичным ключом
        var receiveData = rsaProvider_Receiver.Decrypt(sendData, false);
        var receivedText = Encoding.UTF8.GetString(receiveData);

    }

}


