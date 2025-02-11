using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Riuta
{
    internal static class Helper
    {
        internal static long FindIndexOf(this Span<byte> haystack, Span<byte> needle, long startOffset = 0)
        {
            for (long i = startOffset; i <= haystack.Length - needle.Length; i++)
            {
                if (haystack.Slice((int)i, needle.Length).SequenceEqual(needle))
                {
                    return i;
                }
            }
            return -1;
        }
    }
}
