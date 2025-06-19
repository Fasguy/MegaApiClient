namespace CG.Web.MegaApiClient
{
  using System;
  using System.Security.Cryptography;

  public static class Hashcash
  {
    public class UnknownHashcashVersionException : Exception
    {
      public UnknownHashcashVersionException(string message) : base(message)
      {
      }
    }

    /// <summary>
    /// Generates a response token, based on the challenge provided by MEGA during a network request.
    /// </summary>
    /// <remarks>
    /// This is largely transpiled from https://github.com/qgustavor/mega/blob/main/lib/crypto/index.mjs#L171.
    /// Licensed under MIT.
    /// </remarks>
    /// <param name="challenge">The challenge sent by MEGA in the X-Hashcash response header.</param>
    /// <returns>The proof-of-work token calculated from the challenge.</returns>
    /// <exception cref="UnknownHashcashVersionException">An implementation to solve the requested Hashcash challenge is missing.</exception>
    public static string GenerateToken(string challenge)
    {
      // Split challenge string
      var parts = challenge.Split(':');
      var version = int.Parse(parts[0]);
      if (version != 1)
      {
        throw new UnknownHashcashVersionException($"Hashcash challenge using an unknown version. Expected version 1, got {version}.");
      }

      var easiness = int.Parse(parts[1]);
      var tokenStr = parts[3];

      var token = FromBase64UrlString(tokenStr);

      var baseValue = ((easiness & 63) << 1) + 1;
      var shifts = (easiness >> 6) * 7 + 3;
      var threshold = (uint)(baseValue << shifts);

      const int BufferSize = 4 + 262144 * 48;
      var buffer = new byte[BufferSize];

      for (var i = 0; i < 262144; i++)
      {
        Buffer.BlockCopy(token, 0, buffer, 4 + i * 48, token.Length);
      }

      while (true)
      {
        byte[] hash;
        using (var sha256 = SHA256.Create())
        {
          hash = sha256.ComputeHash(buffer);
        }

        var hashPrefix = BitConverter.ToUInt32(hash, 0);
        if (BitConverter.IsLittleEndian)
        {
          hashPrefix = ReverseBytes(hashPrefix);
        }

        if (hashPrefix <= threshold)
        {
          var prefixEncoded = ToBase64UrlString(buffer[..4]);
          return $"1:{tokenStr}:{prefixEncoded}";
        }

        var j = 0;
        while (true)
        {
          buffer[j]++;
          if (buffer[j++] != 0) break;
        }
      }
    }

    // Unsure if making these url-safe is actually required, since the header should be able to use regular base64 just fine, no?
    // I'm mainly just using them here, since they're used in the original implementation (https://github.com/qgustavor/mega/blob/main/lib/crypto/index.mjs#L13).
    // TODO: Check that and replace if possible.
    private static byte[] FromBase64UrlString(string base64Url)
    {
      var padded = base64Url.Replace('-', '+').Replace('_', '/');
      switch (padded.Length % 4)
      {
        case 2: padded += "=="; break;
        case 3: padded += "="; break;
      }

      return Convert.FromBase64String(padded);
    }

    private static string ToBase64UrlString(byte[] bytes)
    {
      return Convert.ToBase64String(bytes)
        .Replace("+", "-")
        .Replace("/", "_")
        .Replace("=", "");
    }

    private static uint ReverseBytes(uint value)
    {
      return (value >> 24) |
             ((value >> 8) & 0x0000FF00) |
             ((value << 8) & 0x00FF0000) |
             (value << 24);
    }
  }
}
