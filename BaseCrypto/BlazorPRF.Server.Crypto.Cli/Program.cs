using BlazorPRF.Server.Crypto;

if (args.Length == 0)
{
    PrintUsage();
    return 0;
}

var command = args[0].ToLowerInvariant();

try
{
    return command switch
    {
        "verify" => Verify(args),
        "sign" => Sign(args),
        "keygen" => KeyGen(),
        "pubkey" => PubKey(args),
        _ => PrintUsage()
    };
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

static int PrintUsage()
{
    Console.WriteLine("""
        BlazorPRF.Wasm.Crypto CLI - Ed25519 Sign/Verify Tool

        Compatible with BlazorPRF.Wasm.Crypto TypeScript implementation.

        Commands:
          verify <message> <signature> <publicKey>  Verify a signature
          sign <message> <privateKey>               Sign a message
          keygen                                    Generate a new key pair
          pubkey <privateKey>                       Derive public key from private key

        Examples:
          # Verify a signature from BlazorPRF.Wasm.Crypto
          blazorprfserver-cli verify "Hello" "sig..." "pubkey..."

          # Generate a new key pair
          blazorprfserver-cli keygen

          # Sign a message
          blazorprfserver-cli sign "Hello" "privatekey..."

        All keys and signatures are Base64 encoded.
        """);
    return 0;
}

static int Verify(string[] args)
{
    if (args.Length < 4)
    {
        Console.Error.WriteLine("Usage: verify <message> <signature> <publicKey>");
        return 1;
    }

    var message = args[1];
    var signature = args[2];
    var publicKey = args[3];

    var isValid = Ed25519.Verify(message, signature, publicKey);

    Console.WriteLine(isValid ? "Valid: true" : "Valid: false");
    return isValid ? 0 : 1;
}

static int Sign(string[] args)
{
    if (args.Length < 3)
    {
        Console.Error.WriteLine("Usage: sign <message> <privateKey>");
        return 1;
    }

    var message = args[1];
    var privateKey = args[2];

    var signature = Ed25519.Sign(message, privateKey);
    var publicKey = Ed25519.GetPublicKey(privateKey);

    Console.WriteLine($"Message: {message}");
    Console.WriteLine($"Signature: {signature}");
    Console.WriteLine($"PublicKey: {publicKey}");
    return 0;
}

static int KeyGen()
{
    var (privateKey, publicKey) = Ed25519.GenerateKeyPair();

    Console.WriteLine($"PrivateKey: {privateKey}");
    Console.WriteLine($"PublicKey: {publicKey}");
    return 0;
}

static int PubKey(string[] args)
{
    if (args.Length < 2)
    {
        Console.Error.WriteLine("Usage: pubkey <privateKey>");
        return 1;
    }

    var privateKey = args[1];
    var publicKey = Ed25519.GetPublicKey(privateKey);

    Console.WriteLine($"PublicKey: {publicKey}");
    return 0;
}
