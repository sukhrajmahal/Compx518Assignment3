using System;
using System.IO;
using System.Security.Cryptography;
using System.Numerics;

namespace AES
{
    class MainClass
    {
        // Variables that will be parsed from user input are stored here to avoid
        // The use of pointers or tuples to return multiple variables
        // From parseInput method. Feedback on design choice appreciated. 
        static string inputFileName;
        static string hexIVString;

        public static void Main(string[] args)
        {
            // Checking that the inputs are correct order. I.e. Correct flags and strings
            var validFormartInputs = parseInputs(args);
            if (!validFormartInputs)
            {
                return;
            }

            // Checking the arguements that we parsed are actually valid. I.e. IV is valid
            // the file actually exists. 
            var validInputs = checkValidInputs();
            if (!validInputs)
            {
                return;
            }

            //Setting up the key
            var keyString = "770A8A65DA156D24EE2A093277530142";
            byte[] keyBytes = getBytesFromHexString(keyString);

            //Setting up the IV
            byte[] ivBytes = null;
            if (hexIVString != null)
            {
                ivBytes = getBytesFromHexString(hexIVString);
            }

            // Carrying out ECB Encryption
            aesEncryptFile(CipherMode.ECB, keyBytes, ivBytes, inputFileName, "data-ecb.jpg");
            // Carrying out CBC Encryption
            aesEncryptFile(CipherMode.CBC, keyBytes, ivBytes, inputFileName, "data-cbc.jpg");
            // Carring out CFB Encrpytion
            aesEncryptFile(CipherMode.CFB, keyBytes, ivBytes, inputFileName, "data-cfb.jpg");
        }

        private static void aesEncryptFile(CipherMode mode, byte[] keyBytes, byte[] ivBytes, string inputFile, string outputFile)
        {
            //Setting Up the AES object
            Aes aes = Aes.Create();
            aes.Mode = mode;
            aes.Key = keyBytes;

            //For ECB it will ignore the IV anyway so we dont have to worry about checking mode
            if (ivBytes != null)
            {
                aes.IV = ivBytes;
            }
            else
            {
                // In the case where the user has not provided the IV
                // It will print the IV to the console. We would not usally do
                // this. But this allows me to check my output.
                printIV(aes.IV);
            }

            // The Assignment doesn't seem require us to create code that will decrpyt the file as well.
            // However, if you wanted to decrypt as well, it would be the same code as this method except
            // here you would call aes.CreateDecryptor(). 
            ICryptoTransform cryptoTransform = aes.CreateEncryptor();

            // Here we open the input file
            using (FileStream outputFileStream = new FileStream(outputFile, FileMode.Create))
            {
                using (CryptoStream cryptoStream = new CryptoStream(outputFileStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    // We are reading in blocks in a time just to make it a bit faster
                    var totalBytesRead = 0;
                    var offset = 0;

                    // This is how many bits per block we read in a time. However, it
                    // However, this has nothing do with AES block size. We could choose
                    // any block size. But we might as well use the AES block size and
                    // hopefully save some padding.
                    int inputBlockSize = 128;
                    byte[] inputData = new byte[inputBlockSize];

                    using (FileStream inputFileStream = new FileStream(inputFile, FileMode.Open))
                    {
                        var bytesRead = 0;
                        do
                        {
                            bytesRead = inputFileStream.Read(inputData, 0, inputBlockSize);
                            offset += bytesRead;
                            // The Crypto Stream will use the transformer we declared above
                            // to actually carry out the transformation. 
                            cryptoStream.Write(inputData, 0, bytesRead);
                            totalBytesRead += bytesRead;
                        }
                        while (bytesRead > 0);

                        inputFileStream.Close();
                    }

                    cryptoStream.FlushFinalBlock();
                    cryptoStream.Close();
                }
                outputFileStream.Close();
            }
        }

        private static byte[] getBytesFromHexString(string hexNumber)
        {
            // We append 0 to the front of the string so that when we parse it into a BigInt it will
            // know that the nuber is positive. 
            var hexString = "0" + hexNumber;
            var hexBigInt = BigInteger.Parse(hexString, System.Globalization.NumberStyles.HexNumber);
            var hexBytes = hexBigInt.ToByteArray();
            // We reverse the bytes because big int stores the bytes in the wrong endian for us. 
            Array.Reverse(hexBytes);
            // As we added the 0 to make the number positive. Sometimes this will return a byte array
            // with length 17. So we are replacing the extra byte (which is just 0).
            // This is important becasue AES properties require Block Size / 8 long byte arrays.
            if (hexBytes.Length == 17)
            {
                var hexTwoBytes = new byte[16];
                Array.Copy(hexBytes, 1, hexTwoBytes, 0, 16);
                return hexTwoBytes;
            }
            return hexBytes;
        }

        private static void printIV(byte[] ivBytes)
        {
            // Reversing bytes so that they are in little endian
            Array.Reverse(ivBytes);
            BigInteger ivBigInt = new BigInteger(ivBytes);
            // Passing 'x' to the ToString method means the number will be printed in hex
            Console.WriteLine("IV: " + ivBigInt.ToString("x"));
        }

        private static void printHelpMessage()
        {
            Console.WriteLine("AES 128 Bit ENCRYPT");
            Console.WriteLine();
            Console.WriteLine("This program will encrpyt a given file using AES 128 Bit Encryption");
            Console.WriteLine("It will encrpyt the input file with ECB, CBC and CFB modes. Resulting");
            Console.WriteLine("in 3 output files. One for each mode");
            Console.WriteLine();
            Console.WriteLine("Usage: --IV {IV Value} {input file}");
            Console.WriteLine("IV: --IV {Value}: [OPTIONAL] Pass in the IV you would like to use for CBC and CFB mode. IV must be in Hex");
            Console.WriteLine("                  and must be a 128bit number. So the IV must be 32 characters long. The user must pad the");
            Console.WriteLine("                  number if required. If you do not provide a IV value, a random IV will be generated and used.");
            Console.WriteLine("Input File: Path to the file to be input file.");
            Console.WriteLine();
            Console.WriteLine("--help: Prints Help");
        }

        private static bool parseInputs(string[] args)
        {
            // User has passed in one input. This means that they either typed help
            // Or just provided the input file and nothing else.
            if (args.Length == 1)
            {
                // Would have split each case into its own check but C# does not do lazy evaluation
                if (args[0].Equals("--help"))
                {
                    printHelpMessage();
                    // Here we return false even though its valid inpiut because we have printed
                    // help but dont want the program to continue. 
                    return false;
                }
                else
                {
                    inputFileName = args[0];
                    return true;
                }
            }
            else if (args.Length == 3)
            {
                if (args[0].Equals("--IV"))
                {
                    hexIVString = args[1];
                    inputFileName = args[2];
                    return true;
                }
                printHelpMessage();
                return false;
            }
            else
            {
                printHelpMessage();
                return false;
            }
        }

        private static bool checkValidInputs()
        {
            // Checking that the file exists
            if (!File.Exists(inputFileName))
            {
                Console.WriteLine("Please pass in a valid file.");
                return false;
            }

            // Checking if the IV is set correctly
            // If its null then the user has not provided an IV.
            // which is fine.
            if (hexIVString != null)
            {
                // Checking that the IV is 32 characters long (128 bit number)
                // Padding is the duty of the user.
                if (hexIVString.Length != 32)
                {
                    Console.WriteLine("The IV must be a 128 bit Hex Number. If padding is required," +
                        "it must be done before passing it in. Please check that the IV is 32 Characters long");
                    return false;
                }

                // Checking that it string is fully hex
                foreach (char character in hexIVString)
                {
                    // Sourced From: https://stackoverflow.com/questions/223832/check-a-string-to-see-if-all-characters-are-hexadecimal-values
                    // The Regex method seemed over the top for the situation.
                    // Solutions sugesting try parse were not used because BigInt.TryParse would result in the creation of un-needed BigInt
                    var isHexChar = (character >= '0' && character <= '9') ||
                                    (character >= 'a' && character <= 'f') ||
                                    (character >= 'A' && character <= 'F');
                    if (!isHexChar)
                    {
                        Console.WriteLine("Please make sure IV is provided in hex");
                        return false;
                    }
                }
                return true;
            }
            return true;
        }
    }
}