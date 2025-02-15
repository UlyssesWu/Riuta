namespace Riuta
{
    internal static class Helper
    {
        internal static long FindIndexOf(this in Span<byte> haystack, in ReadOnlySpan<byte> needle, long startOffset = 0)
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
