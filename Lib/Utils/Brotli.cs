using System;
using System.Collections.Generic;
using System.Text;
using System.IO.Compression;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Brotli
    {
        static BrotliDecoder bd = new BrotliDecoder();
        static BrotliEncoder be = new BrotliEncoder();
        public static Span<byte> EncodeString(string s)
        {
            Span<byte> b = new Span<byte>();
            ReadOnlySpan<byte> input = new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes(s));
            be.Compress(source: input, destination: b, bytesConsumed: out _, bytesWritten: out _, isFinalBlock: true);
            return b;
        }

        public static string DecodeString(Span<byte> src)
        {
            Span<byte> dest = new Span<byte>();
            bd.Decompress(source: src, destination: dest, bytesConsumed: out _, bytesWritten: out _);
            return Encoding.UTF8.GetString(dest);
        }
    }
}
