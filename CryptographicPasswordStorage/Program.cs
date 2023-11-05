using System.Security.Cryptography;
using Spectre.Console;
using CryptographicPasswordStorage.Code;

AnsiConsole.Write(new FigletText("Cryptography .NET Demo").Centered().Color(Color.Green));

var password = "itsAPassword";

byte[] salt;

var hashedPassword = CryptographyHandler.HashPassword(password, out salt);

var isVerifiable = CryptographyHandler.VerifyPassword(password, hashedPassword, salt);

Console.WriteLine($"Original Password: {password}");
Console.WriteLine($"Hashed Password:   {hashedPassword}");
Console.WriteLine($"Salt:              {salt.Length}");
Console.WriteLine($"Verified:          {isVerifiable}");

Console.WriteLine();

var original = "Here is some data to encrypt! Can it be decrypted?";

// Create a new instance of the Aes
// class.  This generates a new key and initialization
// vector (IV).
using (var myAes = Aes.Create())
{
    // Encrypt the string to an array of bytes.
    var encrypted = CryptographyHandler.Encrypt(original, myAes.Key, myAes.IV);

    // Decrypt the bytes to a string.
    var roundtrip = CryptographyHandler.Decrypt(encrypted, myAes.Key, myAes.IV);

    //Display the original data and the decrypted data.
    Console.WriteLine("Original:   {0}", original);
    Console.WriteLine("Encrypted:  {0}", encrypted.Length);
    Console.WriteLine("Round Trip: {0}", roundtrip);
}