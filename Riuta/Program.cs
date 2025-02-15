// こちとら凡人代表で / 少ないメモリで天手古舞
using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using AsmResolver;
using AsmResolver.PE.File;

namespace Riuta
{
    internal class Program
    {
        public const int EntrySize = 32;

        static void Main(string[] args)
        {
            Console.WriteLine("Tauri Asset Extractor");
            Console.WriteLine("by Ulysses, wdwxy12345@gmail.com");
            Console.WriteLine();

            if (args.Length < 1)
            {
                Console.WriteLine("Usage: .exe <path to Tauri executable>");
                return;
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine("File not found.");
                return;
            }

            string indexFile = string.Empty;
            if (args.Length > 1)
            {
                indexFile = args[1];
            }

            Extract(args[0], indexFile);

            Console.WriteLine("Done.");
#if DEBUG
            Console.ReadLine();
#endif
        }

        static void Extract(string path, string indexFile = "")
        {
            if (string.IsNullOrWhiteSpace(indexFile))
            {
                indexFile = "/index.html";
            }

            PEFile peFile = PEFile.FromFile(path);
            var imageBase = peFile.OptionalHeader.ImageBase;
            var rdata = peFile.Sections.First(s => s.Name == ".rdata");
            var rdataBuffer = rdata.ToArray();
            var rdataSpan = rdataBuffer.AsSpan();
            var rdataStart = imageBase + rdata.Rva;
            var rdataEnd = rdataStart + rdata.GetPhysicalSize();

            ulong ToDataOffset(ulong address)
            {
                return address - imageBase - rdata.Rva;
            }

            bool InSection(ulong address)
            {
                return address >= rdataStart && address < rdataEnd;
            }

            ulong ToVirtualAddress(int offset)
            {
                return imageBase + rdata.Rva + (uint) offset;
            }

            // Find the index file in the .rdata section
            int index = 0;
            int refIndex = -1;
            Span<byte> addressBytes = stackalloc byte[8];
            do
            {
                var l = rdataSpan.FindIndexOf(Encoding.UTF8.GetBytes(indexFile), index);
                if (l > int.MaxValue)
                {
                    break;
                }

                index = (int) l;

                if (index >= 3)
                {
                    //get previous 3 bytes
                    var offset = index - 3;
                    var sample = rdataSpan.Slice(offset, 3);
                    if (sample.SequenceEqual("to "u8))
                    {
                        // ` not found; fallback to index.html\0', not what we want
                        continue;
                    }

                    offset = index + 1;
                    if (offset >= rdataSpan.Length)
                    {
                        continue;
                    }

                    if (rdataSpan[offset] == 0)
                    {
                        continue; // there should be something
                    }

                    // check xref
                    var address = ToVirtualAddress(index);

                    BinaryPrimitives.WriteUInt64LittleEndian(addressBytes, address);

                    int refIdx = 0;
                    do
                    {
                        refIdx = (int) rdataSpan.FindIndexOf(addressBytes, refIdx);

                        if (refIdx < 0)
                        {
                            break;
                        }

                        var fileNameLength = BinaryPrimitives.ReadInt64LittleEndian(rdataSpan.Slice(refIdx + 8, 8));
                        if (fileNameLength == indexFile.Length)
                        {
                            //check filePtr
                            var filePtr = BinaryPrimitives.ReadUInt64LittleEndian(rdataSpan.Slice(refIdx + 16, 8));
                            var offsetDelta = filePtr - address;
                            if (offsetDelta >= (ulong)fileNameLength + 16) // not the valid one
                            {
                                refIdx += 1;
                                continue;
                            }

                            refIndex = refIdx;
                            break;
                        }
                    } while (refIdx > 0);

                    if (refIndex >= 0)
                    {
                        break;
                    }

                    index += 1;
                }
            } while (index >= 0);

            if (refIndex < 0)
            {
                Console.WriteLine("Failed: Cannot find pattern.");
                return;
            }

            var baseDir = Path.GetDirectoryName(path) ?? "";
            var fileName = Path.GetFileNameWithoutExtension(path);
            var extractDir = Path.Combine(baseDir, $"{fileName}_extract");
            try
            {
                Directory.CreateDirectory(extractDir);
            }
            catch (Exception)
            {
                extractDir = $"{fileName}_extract";
                try
                {
                    Directory.CreateDirectory(extractDir);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed: Could not create directory.");
                    Console.WriteLine(ex);
                    return;
                }
            }

            int dumpCount = 0;

            bool Dump(int offset, string basePath, in Span<byte> rdataSpan)
            {
                if (offset < 0 || offset > rdataSpan.Length - EntrySize)
                {
                    return false;
                }

                var fileNamePtr = BinaryPrimitives.ReadUInt64LittleEndian(rdataSpan.Slice(offset, 8));
                if (!InSection(fileNamePtr))
                {
                    return false;
                }

                int fileNameLength = (int) BinaryPrimitives.ReadInt64LittleEndian(rdataSpan.Slice(offset + 8, 8));
                if (fileNameLength <= 0 || fileNameLength > rdataSpan.Length)
                {
                    return false;
                }

                var dataPtr = BinaryPrimitives.ReadUInt64LittleEndian(rdataSpan.Slice(offset + 16, 8));
                if (!InSection(dataPtr))
                {
                    return false;
                }

                var dataLength = (int) BinaryPrimitives.ReadInt64LittleEndian(rdataSpan.Slice(offset + 24, 8));
                if (dataLength < 0 || dataLength > rdataSpan.Length)
                {
                    return false;
                }

                try
                {
                    var assetName = Encoding.UTF8.GetString(rdataSpan.Slice((int) ToDataOffset(fileNamePtr), fileNameLength));
                    assetName = assetName.TrimStart('/');

                    //BrotliStream level 9
                    var dataStartOffset = (int) ToDataOffset(dataPtr);
                    byte[] decompressData = [];
                    try
                    {
                        decompressData = Decompress(rdataBuffer, dataStartOffset, dataLength);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"Error when decompress {fileName}: {e.Message}");
                    }

                    if (decompressData.Length == 0 && dataLength > 0)
                    {
                        decompressData = rdataSpan.Slice(dataStartOffset, dataLength).ToArray();
                    }

                    var extractFileName = Path.Combine(basePath, assetName);
                    //ensure directory
                    Directory.CreateDirectory(Path.GetDirectoryName(extractFileName) ?? "");
                    File.WriteAllBytes(extractFileName, decompressData);
                    Console.WriteLine(
                        $"Extract {offset:X8}|{ToVirtualAddress(offset):X16}: {assetName} ({dataLength} -> {decompressData.Length})");
                    dumpCount++;
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Error when extracting {fileName}: {e}");
                }

                return true;
            }

            bool flag = true;
            int currentOffset = refIndex;
            while (flag)
            {
                flag = Dump(currentOffset, extractDir, rdataSpan);
                if (flag)
                {
                    currentOffset += EntrySize;
                }
            }

            //reverse direction
            flag = true;
            currentOffset = refIndex - EntrySize;
            while (flag)
            {
                flag = Dump(currentOffset, extractDir, rdataSpan);
                if (flag)
                {
                    currentOffset -= EntrySize;
                }
            }

            Console.WriteLine($"{dumpCount} file extracted.");
        }

        public static byte[] Decompress(byte[] value, int start, int length)
        {
            using var input = new MemoryStream(value, start, length, false);
            using var output = new MemoryStream();
            using var stream = new BrotliStream(input, CompressionMode.Decompress);

            stream.CopyTo(output);
            stream.Flush();

            return output.ToArray();
        }

        public static byte[] Compress(byte[] value)
        {
            using var input = new MemoryStream(value);
            using var output = new MemoryStream();
            using var stream = new BrotliStream(output, new BrotliCompressionOptions() {Quality = 9});
            input.CopyTo(stream);
            stream.Flush();
            return output.ToArray();
        }
    }
}
