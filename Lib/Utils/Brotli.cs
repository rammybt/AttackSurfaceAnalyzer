using System;
using System.Text;
using System.IO.Compression;
using System.Linq;
using Serilog;
using System.Buffers;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class Brotli
    {
        public static int savedBytes = 0;
        public static Span<byte> EncodeString(string s)
        {
            ReadOnlySpan<byte> input = new ReadOnlySpan<byte>(Encoding.UTF8.GetBytes(s));
            byte[] a = new byte[input.Length];
            Span<byte> b = new Span<byte>(a);
            int bytesWritten;
            BrotliEncoder.TryCompress(source: input,
                            destination: b,
                            bytesWritten: out bytesWritten);
            Span<byte> o = b.Slice(0, bytesWritten);
            byte[] sp = o.ToArray();
            savedBytes += input.Length - bytesWritten;

            return b;
        }

        public static string DecodeString(Span<byte> src)
        {
            // Testing found our strings were compressed by about 50%. Benchmarks show it can get up to 10 fold. These are pretty small things, so over allocating is better than not properly decompressing.
            int multiplier = 2;
            bool keepgoing = true;
            Span<byte> o = new Span<byte>();
            while (keepgoing)
            {
                byte[] space = new byte[src.Length * multiplier];
                Span<byte> dest = new Span<byte>(space);
                int bytesWritten;
                BrotliDecoder.TryDecompress(source: src, destination: dest, bytesWritten: out bytesWritten);
                if (bytesWritten == space.Length)
                {
                    Log.Debug("Overflow brotli decoding at {0}X",multiplier);
                    multiplier *= 2;
                    continue;
                }
                keepgoing = false;
                o = dest.Slice(0, bytesWritten);
            }

            return Encoding.UTF8.GetString(o);
        }
    }
}
